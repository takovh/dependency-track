# EUVD API 漏洞数据库同步可行性分析

## 结论

基于现有 EUVD API，可以实现 EUVD 漏洞数据的全量同步和增量同步，但需要明确以下边界：

- 可以可靠实现 EUVD 漏洞元数据的本地镜像。
- 可以同步 CVE/EUVD 映射、CVSS、EPSS、KEV、厂商和产品信息。
- 仅依靠现有 EUVD API，无法可靠实现 Dependency-Track 所需的“组件版本—漏洞”精确匹配。

EUVD 更适合作为漏洞聚合与情报增强数据源，而不是唯一的组件漏洞匹配数据源。

## 能力评估

| 能力 | 可行性 | 说明 |
| --- | --- | --- |
| 漏洞条目全量同步 | 高 | `/api/search` 支持分页，单页最多返回 100 条 |
| 按更新时间增量同步 | 较高 | 支持 `fromUpdatedDate` 和 `toUpdatedDate` |
| CVE/EUVD 标识映射 | 高 | 提供每日更新的完整 CSV |
| KEV 已利用状态同步 | 高 | 提供完整 JSON dump |
| CVSS、EPSS、引用同步 | 高 | 搜索结果直接包含相关字段 |
| 厂商、产品同步 | 中 | 包含厂商、产品和版本描述，但格式未标准化 |
| 软件包精确匹配 | 低 | 没有 PURL、CPE、生态信息或标准化版本区间 |
| 删除、撤回同步 | 低 | 没有 tombstone、删除列表或变更事件流 |

相关接口定义参见 [EUVD-API-Documentation.md](EUVD-API-Documentation.md)，响应示例参见 [EUVD-API-Example.md](EUVD-API-Example.md)。

## 可用于同步的 API

### 漏洞搜索

```http
GET https://euvdservices.enisa.europa.eu/api/search
```

与同步相关的主要参数：

- `fromDate`、`toDate`：按发布时间筛选。
- `fromUpdatedDate`、`toUpdatedDate`：按更新时间筛选。
- `page`：页码，从 0 开始。
- `size`：每页记录数，最大为 100。
- `exploited`：筛选已知被利用的漏洞。
- `product`、`vendor`、`assigner`：按数据属性筛选。

响应主要由以下字段组成：

```json
{
  "items": [],
  "total": 389928
}
```

### 查询单个 EUVD 漏洞

```http
GET https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-45012
```

可用于重新获取单条漏洞的详细信息，但不适合替代分页批量同步。

### CVE 与 EUVD ID 映射

```http
GET https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping
```

该接口提供完整 CSV，字段为：

```csv
euvd_id,cve_id
```

数据每日 07:00 UTC 更新，只包含已经关联到已发布 CVE 的记录。

### KEV 数据

```http
GET https://euvdservices.enisa.europa.eu/api/kev/dump
```

该接口提供完整的 CISA KEV 和 ENISA EU KEV 聚合数据，主要字段包括：

- `cveId`
- `euvdId`
- `dateAdded`
- `sources`

## 线上接口验证结果

对公开 EUVD API 进行了只读验证，结果如下：

- `/api/search` 返回 `items` 和 `total`。
- 验证时总数据量约为 389,928 条。
- `size=101` 会被服务端静默限制为 100 条。
- 请求超出范围的页码会返回 HTTP 200 和空的 `items` 数组。
- 请求不存在的 EUVD ID 会返回 HTTP 204，响应体为空。
- `fromUpdatedDate` 晚于 `toUpdatedDate` 时，接口返回 HTTP 200 和空结果，而不是参数错误。
- 负数页码被当作第一页处理，客户端不能依赖服务端完成参数校验。
- 默认结果在验证时表现为按 `dateUpdated` 倒序排列，但 API 文档没有承诺排序规则。
- 响应没有提供明确的速率限制、ETag、数据版本号或快照标识。

按验证时约 389,928 条数据计算，以每页 100 条进行全量同步，至少需要约 3,900 次请求。

## 推荐的数据库模型

建议至少包含以下逻辑表或等效数据结构。

### 漏洞主表

以 `euvd_id` 为稳定主键，保存：

- EUVD ID
- ENISA UUID
- 描述
- 发布时间
- 更新时间
- CVSS 分数、版本和向量
- EPSS
- 分配机构
- 是否已知被利用及利用日期
- 原始 JSON
- 首次同步时间
- 最后同步时间

### 漏洞别名表

将换行分隔的 `aliases` 拆分保存，例如：

- CVE ID
- GHSA ID
- 其他漏洞编号

建议对“别名类型 + 别名值”建立索引，但不要直接假设一个 CVE 只会对应一个 EUVD 数据对象。

### 引用表

将换行分隔的 `references` 拆分为独立 URL，并按照 EUVD ID 建立关联。

### 厂商、产品和受影响版本表

保存以下原始信息：

- 厂商名称
- 产品名称
- `product_version` 原始文本

`product_version` 应首先作为原始字符串保存。只有在能够确认语法时，才额外生成结构化的版本范围。

### KEV 表

保存 CVE ID、EUVD ID、加入日期和来源，并允许每日用完整 dump 进行覆盖或 upsert。

## 全量同步方案

### 基本流程

1. 调用 `/api/search`，将 `size` 设置为 100。
2. 分页读取数据，直到达到 `total` 或当前页返回空数组。
3. 以 EUVD ID 为主键执行幂等 upsert。
4. 保留每条记录的原始 JSON，便于 API 字段变化后重新解析。
5. 下载 CVE/EUVD 映射 CSV，建立别名索引。
6. 下载 KEV JSON，补充已知被利用状态。

### 日期窗口

不建议仅使用一个无日期限制的大型分页任务。同步期间如果服务端新增或更新数据，基于偏移量的分页结果可能移动，从而造成重复或遗漏。

建议按照 `dateUpdated` 将数据拆分为固定日期窗口：

```text
fromUpdatedDate=YYYY-MM-DD
toUpdatedDate=YYYY-MM-DD
page=0..N
size=100
```

可以根据单个窗口的 `total` 动态调整窗口大小：

- 数据量较少时按月同步。
- 数据量较多时按日同步。
- 对正在发生变化的当天数据使用独立任务重复扫描。

首次同步还可以补充执行一次无日期过滤的全量扫描，以发现缺少 `dateUpdated` 或日期异常的记录。

## 增量同步方案

EUVD API 的日期过滤只精确到天，不能使用精确到秒的更新时间作为游标。因此，增量任务必须采用重叠时间窗口。

推荐范围：

```text
同步开始日期 = 上次成功同步日期 - 1～2 天
同步结束日期 = 当前日期
```

推荐调度策略：

- 每小时重新扫描今天和昨天的数据。
- 每天重新扫描最近 7 天的数据。
- 定期进行一次完整数据核对。
- 所有写入均使用 EUVD ID 执行幂等 upsert。
- 任意分页失败时，重新执行整个日期窗口，而不是只从失败页继续。

### 当前日期窗口的分页漂移

正在更新的日期窗口可能在分页过程中发生记录插入或排序变化。可以采用以下方法降低遗漏概率：

1. 完整扫描当前日期窗口。
2. 记录扫描前后的 `total`、第一页 ID 和最后更新时间。
3. 如果关键值发生变化，则重新扫描该窗口。
4. 日期结束后，再执行一次完整的封账扫描。

不要依赖接口当前表现出的默认排序作为增量游标，因为排序行为未在文档中明确保证。

## 字段处理注意事项

### 日期

响应日期采用类似下面的英文展示格式：

```text
Aug 26, 2026, 11:21:07 PM
```

API 没有明确说明时区。建议：

- 使用固定英文区域设置解析。
- 保留原始日期字符串。
- 数据库内部统一转换为 UTC，但在确认服务端时区前标记其时区来源。
- 增量查询至少重叠 1～2 天，降低时区边界造成的遗漏风险。

### 别名和引用

`aliases` 和 `references` 是换行分隔字符串，而不是 JSON 数组。解析时应：

- 按换行拆分。
- 去除前后空白。
- 丢弃空项。
- 对 URL 或别名执行去重。

### EPSS

文档中的 EPSS 查询范围是 0～100，而部分目标系统可能使用 0～1 的概率值。同步到其他系统前，需要确认目标字段的量纲，必要时除以 100，并保留 EUVD 原始值。

### 产品版本

`product_version` 是非结构化文本，可能出现：

```text
10.0.26200.0 <10.0.26200.9168
-
n/a
https://example.com/security-releases
```

因此不能对所有记录统一套用语义化版本比较。建议同时保存：

- `raw_version_range`
- 解析状态
- 解析后的起始版本
- 解析后的结束版本
- 边界是否包含
- 解析规则或数据来源

无法可靠解析时，只保存原始值，不参与自动漏洞匹配。

## 删除和撤回处理

现有 API 没有提供：

- 删除记录列表
- tombstone
- 变更事件流
- 数据集版本号
- 完整漏洞 dump

因此，不应因为某条记录没有出现在一次增量结果中就删除本地数据。

建议：

- 默认只执行新增和更新。
- 对长期未出现的记录标记为“待核对”，而不是立即删除。
- 必要时使用 `/api/enisaid` 单条核对；HTTP 204 表示当前无法查到该 ID，但仍建议保留审计记录。
- 定期执行全量 ID 对账，再由明确的业务策略决定是否软删除。

## 与 Dependency-Track 集成的限制

Dependency-Track 要判断一个组件是否受漏洞影响，通常需要至少一种标准化关联信息：

- Package URL（PURL）
- CPE
- 软件生态和包名
- 可机器解析的受影响版本范围

EUVD 当前返回的厂商、产品和 `product_version` 主要是自然语言或来源相关格式，没有稳定的 PURL、CPE 或统一版本区间。因此仅靠这些字段，很难可靠匹配 Maven、npm、PyPI、NuGet 等 SBOM 组件。

推荐的数据源职责如下：

```text
NVD / OSV / GitHub Advisory
          │
          ├── 负责 PURL/CPE 与受影响版本匹配
          │
          ▼
Dependency-Track 漏洞关联
          ▲
          │
EUVD ─────┴── 补充 EUVD ID、CVSS、EPSS、KEV、厂商和引用
```

### 推荐集成定位

如果目标是 Dependency-Track，建议将 EUVD 定位为增强数据源：

- 使用 CVE 别名与现有 NVD、OSV、GHSA 漏洞记录关联。
- 使用 EUVD 补充 CVSS、EPSS、KEV、引用和欧洲漏洞标识。
- 组件关联仍以 PURL、CPE 或其他结构化包坐标数据源为准。
- 对没有 CVE 别名的 EUVD 记录，可以作为 EUVD 独立漏洞保存，但不能自动关联组件，除非额外建立人工或规则化映射。

如果需要把 EUVD 作为 Dependency-Track 中独立的漏洞来源，通常需要增加自定义同步任务、字段映射和来源标识；不建议把 EUVD ID 强行伪装成 NVD 或 OSV 数据。

## 最终判断

现有 API 足以支持：

- EUVD 漏洞目录的本地镜像。
- CVE/EUVD 映射同步。
- CVSS、EPSS 和引用信息更新。
- KEV 情报同步。
- 按天进行的重叠式增量同步。

现有 API 单独不足以支持：

- 精确的软件包坐标匹配。
- 通用且可靠的受影响版本判断。
- 无遗漏的秒级增量游标。
- 自动识别删除或撤回记录。

因此，可以实施 EUVD 漏洞数据库同步，但应将其设计成“幂等、重叠窗口、定期全量校验”的同步系统；在 Dependency-Track 场景中，应把 EUVD 作为漏洞情报增强源，并与 NVD、OSV、GitHub Advisory 等结构化组件漏洞数据源共同使用。
