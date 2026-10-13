根因是：**EUVD 提供的是包含多个设备系列的描述性产品名，当前转换器却把它当作单个 CPE 的产品标识，完整拼入 CPE，最终超过数据库的 255 字符限制。**

1. **长名称在原始数据中就存在，并非本地合并产生。**

   [EUVD 样本](/home/tako/workspace/dependency-track/vuln-data-source/euvd/doc/euvd-vuln-software-save-db-error/sample1/EUVD-2023-49907.json:14) 的 `enisaIdProduct` 有 10 条记录，使用同一个产品名：

   ```text
   Aruba Access Points: 100 Series; 103 Series; …; 650 Series;
   ```

   原始名称长 **332 字符**，去掉末尾空格后为 **331 字符**。它与 [NVD 样本 `affected` 中的产品名](/home/tako/workspace/dependency-track/vuln-data-source/euvd/doc/euvd-vuln-software-save-db-error/sample1/CVE-2023-45615.json:27) 完全一致。因此需要修正我之前的判断：代码没有把多个产品合并起来，**上游已经将系列列表放在一个名称字段里**。
2. **转换器把展示名称直接转换成 CPE。**

   [EUVD 转换逻辑](/home/tako/workspace/dependency-track/vuln-data-source/euvd/src/main/java/org/dependencytrack/vulndatasource/euvd/ModelConverter.java:138) 固定使用以下结构：

   ```text
   cpe:2.3:a:<vendor>:<整个产品名称>:*:*:*:*:*:*:*:*
   ```

   `cpeField()` 将名称转小写、空白替换成下划线，并转义冒号和分号，但不会拆分产品或检查长度。结果为：

   | 入库字段    | 实际长度 | 限制 |
   | ----------- | -------: | ---: |
   | `PRODUCT` |      331 |  255 |
   | `CPE23`   |      387 |  255 |
   | `CPE22`   |      394 |  255 |

   `CPE22` 中的 `%3a`、`%3b` 等编码进一步增加长度。CPE 解析成功也不代表满足数据库字段长度。
3. **NVD 的结构化匹配数据与这段展示名称不同。**

   [NVD 样本的 `configurations` ](/home/tako/workspace/dependency-track/vuln-data-source/euvd/doc/euvd-vuln-software-save-db-error/sample1/CVE-2023-45615.json:139) 已经给出简短的 CPE，例如：

   ```text
   cpe:2.3:o:arubanetworks:arubaos:*:*:*:*:*:*:*:*
   cpe:2.3:o:hp:instantos:*:*:*:*:*:*:*:*
   ```

   [NVD 转换器](/home/tako/workspace/dependency-track/vuln-data-source/nvd/src/main/java/org/dependencytrack/vulndatasource/nvd/ModelConverter.java:120) 使用这些结构化 CPE，而 EUVD 转换器使用产品展示名称自行生成 CPE。这解释了同一漏洞为何会在 EUVD 导入路径触发超长错误。

此外，这份样本还暴露了两个匹配准确性问题：

- EUVD 产品内的厂商为 `"n/a"`，代码仍将其作为 CPE 厂商；虽然顶层 `enisaIdVendor` 有 HPE，但当前转换没有使用它。
- `ArubaOS 10.4.x.x: 10.4.0.2 and below` 等版本描述不符合当前 `versionRange()` 支持的格式，最终退化为 `vers:generic/*`，再转换成 `versionStartIncluding="0"`，丢失原有版本限制。

所以，**扩容字段只能消除这次入库异常，不能解决生成的 CPE 和版本范围不准确的问题**。修复重点应是避免把描述性产品名直接当作可靠的 CPE 标识；仅按分号拆分，也无法自动得到 NVD 中正确的厂商、产品及版本范围。
