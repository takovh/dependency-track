## Frontpage

### Show latest vulnerabilities



api/lastvulnerabilities


```JSON
[
  {
    "id": "EUVD-2026-63374",
    "enisaUuid": "31b041a5-02ae-3f45-b3f2-c6ee5d68abda",
    "description": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Estonian Information System Authority (RIA) DigiDoc4 client.\n\nThis issue affects DigiDoc4: from 4.0.0 before 4.11.0.",
    "datePublished": "Aug 20, 2026, 2:04:15 PM",
    "dateUpdated": "Aug 26, 2026, 7:51:08 PM",
    "baseScore": 8.4,
    "baseScoreVersion": "4.0",
    "baseScoreVector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "references": "https://github.com/open-eid/libdigidocpp/pull/736\nhttps://github.com/open-eid/DigiDoc4-Client/pull/1402\nhttps://github.com/open-eid/DigiDoc4-Client\n",
    "aliases": "CVE-2026-70383\nGHSA-48r4-r7pv-pj69\n",
    "assigner": "ENISA",
    "epss": 0.15,
    "enisaIdVendor": [
      {
        "id": "62507917-75f2-3f21-a3ad-b06d099eca8c",
        "vendor": {
          "name": "Estonian Information System Authority (RIA)"
        }
      }
    ]
  },
  {
    "id": "EUVD-2026-62704",
    "enisaUuid": "b79f008f-7cf2-3edc-b149-9b1867525ddf",
    "description": "Download of code without integrity check, inclusion of functionality from untrusted control sphere, and cleartext \ntransmission of sensitive information vulnerability in Ozols Grupa OZOLS\n on Windows caused by an abandoned auto-update domain. Affected\ncomponent: the automatic update channel - OzolsSQL client update path, the <db>_update SQL Server Agent job (@subsystem = N'ActiveScripting') and serv_update.vbs.\n\nThis issue affects OZOLS: before 1.1.1233.",
    "datePublished": "Aug 19, 2026, 7:25:10 PM",
    "dateUpdated": "Aug 26, 2026, 7:29:42 PM",
    "baseScore": 10.0,
    "baseScoreVersion": "4.0",
    "baseScoreVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "references": "https://offseq.com/en/research/ozols-cve-2026-22306\n",
    "aliases": "GHSA-xhj7-3r6j-f89h\nCVE-2026-22306\n",
    "assigner": "ENISA",
    "epss": 0.15,
    "enisaIdVendor": [
      {
        "id": "af66f537-ceaa-3736-af50-35ba768664e7",
        "vendor": {
          "name": "Ozols Grupa"
        }
      }
    ]
  },
  {
    "id": "EUVD-2025-14085",
    "enisaUuid": "14c70690-f975-31f6-8c6a-9545d128055c",
    "description": "Improper Input Validation vulnerability in Sparx Systems Pro Cloud Server's WebEA model search field allows Cross-Site Scripting (XSS). \n\n\nThis issue affects Pro Cloud Server: earlier than 6.0.165.",
    "datePublished": "May 9, 2025, 5:12:54 AM",
    "dateUpdated": "Aug 26, 2026, 1:26:17 PM",
    "baseScore": 5.3,
    "baseScoreVersion": "4.0",
    "baseScoreVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "references": "https://sparxsystems.com/products/procloudserver/6.1/\n",
    "aliases": "GHSA-6362-hmcr-gv4j\nCVE-2025-4376\n",
    "assigner": "NCSC-FI",
    "epss": 0.66,
    "enisaIdVendor": [
      {
        "id": "de361594-7b19-34a3-a8fd-5392ccb552f0",
        "vendor": {
          "name": "Sparx Systems"
        }
      }
    ]
  },
  {
    "id": "EUVD-2025-9126",
    "enisaUuid": "8bbd7b45-2162-35f4-9c3d-303c32068c9d",
    "description": "Local privilege escalation through insecure DCOM configuration in Valmet DNA versions prior to C2023. The DCOM object Valmet DNA Engineering has permissions that allow it to run commands as a user with the SeImpersonatePrivilege privilege. The SeImpersonatePrivilege privilege is a Windows permission that allows a process to impersonate another user. An attacker can use this vulnerability to escalate their privileges and take complete control of the system.",
    "datePublished": "Apr 1, 2025, 4:05:14 AM",
    "dateUpdated": "Aug 26, 2026, 1:22:50 PM",
    "baseScore": 8.9,
    "baseScoreVersion": "4.0",
    "baseScoreVector": "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:N/AU:Y/R:U/V:D/RE:H/U:Amber",
    "references": "https://www.valmet.com/about-us/about/research-and-development/vulnerabilityadvisories/cve-2025-0416/\n",
    "aliases": "CVE-2025-0416\nGHSA-23pg-v644-m29h\n",
    "assigner": "NCSC-FI",
    "epss": 0.19,
    "enisaIdVendor": [
      {
        "id": "66ab397a-e392-394d-ab75-37541b023a3a",
        "vendor": {
          "name": "Valmet"
        }
      }
    ]
  }
]
```

### Show latest exploited vulnerabilities

api/exploitedvulnerabilities

```json
[
  {
    "id": "EUVD-2026-40307",
    "enisaUuid": "03e9c52c-a145-3e92-943a-1c23e48ccfde",
    "description": "Memory overflow vulnerability NetScaler ADC and NetScaler Gateway leading to unpredictable or erroneous behavior and Denial of Service if the appliance is configured as a Gateway (SSL VPN, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server",
    "datePublished": "Jun 30, 2026, 12:41:07 PM",
    "dateUpdated": "Aug 26, 2026, 7:58:24 PM",
    "baseScore": 8.8,
    "baseScoreVersion": "4.0",
    "baseScoreVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L",
    "references": "https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696604\n",
    "aliases": "CVE-2026-8452\nGHSA-r7wg-r5wj-c765\n",
    "assigner": "NetScaler",
    "epss": 1.04,
    "exploitedSince": "Aug 26, 2026, 12:00:00 AM",
    "enisaIdVendor": [
      {
        "id": "44f7fd18-3864-36c0-9d8b-c9934fe137dd",
        "vendor": {
          "name": "NetScaler"
        }
      }
    ]
  },
  {
    "id": "EUVD-2021-2466",
    "enisaUuid": "9be5c33d-4556-3e38-86b2-7daf523c85d2",
    "description": "All versions of package ajaxpro.2 are vulnerable to Deserialization of Untrusted Data due to the possibility of deserialization of arbitrary .NET classes, which can be abused to gain remote code execution.",
    "datePublished": "Dec 3, 2021, 8:05:12 PM",
    "dateUpdated": "Aug 26, 2026, 7:58:23 PM",
    "baseScore": 8.1,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "references": "https://snyk.io/vuln/SNYK-DOTNET-AJAXPRO2-1925971\nhttps://github.com/michaelschwarz/Ajax.NET-Professional/commit/b0e63be5f0bb20dfce507cb8a1a9568f6e73de57\nhttp://packetstormsecurity.com/files/175677/AjaxPro-Deserialization-Remote-Code-Execution.html\n",
    "aliases": "CVE-2021-23758\nGHSA-74r6-grj9-8rq6\nGHSA-6r7c-6w96-8pvw\n",
    "assigner": "snyk",
    "epss": 89.1,
    "exploitedSince": "Aug 26, 2026, 12:00:00 AM",
    "enisaIdVendor": [
      {
        "id": "7d47d121-3c3d-3bea-b25a-0a6c513f5892",
        "vendor": {
          "name": "n/a"
        }
      }
    ]
  },
  {
    "id": "EUVD-2022-15988",
    "enisaUuid": "8e33e6f8-32dd-35f0-8398-8b6f3cd2626f",
    "description": "An out-of-bounds (OOB) memory write flaw was found in the Linux kernel’s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.",
    "datePublished": "Mar 25, 2022, 6:03:08 PM",
    "dateUpdated": "Aug 26, 2026, 7:58:24 PM",
    "baseScore": 7.8,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "references": "https://bugzilla.redhat.com/show_bug.cgi?id=2063786\nhttps://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=93ce93587d36493f2f86921fa79921b3cba63fbb\nhttp://packetstormsecurity.com/files/166770/Linux-watch_queue-Filter-Out-Of-Bounds-Write.html\nhttp://packetstormsecurity.com/files/166815/Watch-Queue-Out-Of-Bounds-Write.html\nhttps://security.netapp.com/advisory/ntap-20220429-0001/\n",
    "aliases": "GHSA-q5p3-3mpm-hppr\nCVE-2022-0995\n",
    "assigner": "redhat",
    "epss": 6.34,
    "exploitedSince": "Aug 26, 2026, 12:00:00 AM",
    "enisaIdVendor": [
      {
        "id": "009701a5-1b68-3b1d-80fe-7e7eac9d06c9",
        "vendor": {
          "name": "n/a"
        }
      }
    ]
  },
  {
    "id": "EUVD-2019-9650",
    "enisaUuid": "2930b827-e830-395b-b784-d52d0da19be1",
    "description": "A remote code execution vulnerability exists in Microsoft SQL Server when it incorrectly handles processing of internal functions, aka 'Microsoft SQL Server Remote Code Execution Vulnerability'.",
    "datePublished": "Jul 15, 2019, 6:56:20 PM",
    "dateUpdated": "Aug 26, 2026, 7:58:25 PM",
    "baseScore": 8.8,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "references": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1068\n",
    "aliases": "CVE-2019-1068\nGHSA-62pw-5pr4-ghr5\n",
    "assigner": "microsoft",
    "epss": 44.67,
    "exploitedSince": "Aug 26, 2026, 12:00:00 AM",
    "enisaIdVendor": [
      {
        "id": "3849fe75-a019-355d-869d-d9a80bffbb52",
        "vendor": {
          "name": "Microsoft"
        }
      }
    ]
  }
]
```

### Show latest critical vulnerabilities

api/criticalvulnerabilities

```json
[
  {
    "id": "EUVD-2026-63693",
    "enisaUuid": "6869f008-50e6-307d-bd18-cd889ea8b9a1",
    "description": "Deserialization of untrusted data in Microsoft Entra ID allows an unauthorized attacker to execute code over a network.",
    "datePublished": "Aug 20, 2026, 9:43:12 PM",
    "dateUpdated": "Aug 26, 2026, 11:21:07 PM",
    "baseScore": 10.0,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C",
    "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69836\n",
    "aliases": "CVE-2026-69836\nGHSA-v6wh-624g-vvmv\n",
    "assigner": "microsoft",
    "epss": 1.59,
    "exploitedSince": "Aug 21, 2026, 12:00:00 AM",
    "enisaIdVendor": [
      {
        "id": "434c1e3b-6884-32e9-afc6-28a522367dfb",
        "vendor": {
          "name": "Microsoft"
        }
      }
    ]
  },
  {
    "id": "EUVD-2026-63627",
    "enisaUuid": "4821747b-a430-3207-85ae-23145df555a8",
    "description": "Incorrect authorization in Azure Arc allows an unauthorized attacker to elevate privileges over a network.",
    "datePublished": "Aug 20, 2026, 9:47:11 PM",
    "dateUpdated": "Aug 26, 2026, 11:20:58 PM",
    "baseScore": 10.0,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:U/RL:O/RC:C",
    "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69555\n",
    "aliases": "CVE-2026-69555\nGHSA-m9j2-qfhx-hm42\n",
    "assigner": "microsoft",
    "epss": 0.44,
    "enisaIdVendor": [
      {
        "id": "bc77df69-25e8-3754-97b7-307ffd6680dc",
        "vendor": {
          "name": "Microsoft"
        }
      }
    ]
  },
  {
    "id": "EUVD-2026-63626",
    "enisaUuid": "c94fb25c-29c6-3271-bdcf-7b56cf6e8ccf",
    "description": "Improper limitation of a pathname to a restricted directory ('path traversal') in Azure Logic Apps allows an unauthorized attacker to elevate privileges over a network.",
    "datePublished": "Aug 20, 2026, 9:47:10 PM",
    "dateUpdated": "Aug 26, 2026, 11:20:58 PM",
    "baseScore": 9.6,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C",
    "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69400\n",
    "aliases": "GHSA-66h9-689p-45mg\nCVE-2026-69400\n",
    "assigner": "microsoft",
    "epss": 0.56,
    "enisaIdVendor": [
      {
        "id": "552c6f8d-23e6-358f-9527-e5ab85ad2111",
        "vendor": {
          "name": "Microsoft"
        }
      }
    ]
  },
  {
    "id": "EUVD-2026-63994",
    "enisaUuid": "f08c5405-ddf1-32f1-baf7-355da5f24c62",
    "description": "Server-side request forgery (ssrf) in Azure SQL Database allows an unauthorized attacker to elevate privileges over a network.",
    "datePublished": "Aug 21, 2026, 4:03:56 PM",
    "dateUpdated": "Aug 26, 2026, 11:20:57 PM",
    "baseScore": 10.0,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:P/RL:O/RC:C",
    "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69502\n",
    "aliases": "CVE-2026-69502\nGHSA-cc49-67hv-4hv5\n",
    "assigner": "microsoft",
    "epss": 0.58,
    "enisaIdVendor": [
      {
        "id": "ca8b9f49-7c10-30f1-aeb1-5c3140039d21",
        "vendor": {
          "name": "Microsoft"
        }
      }
    ]
  }
]
```

## Scores & Filters

### Query vulnerabilities with flexible filters

api/search?fromScore=7.5&toScore=10&page=2&size=5

```json
{
  "items": [
    {
      "id": "EUVD-2026-63693",
      "enisaUuid": "6869f008-50e6-307d-bd18-cd889ea8b9a1",
      "description": "Deserialization of untrusted data in Microsoft Entra ID allows an unauthorized attacker to execute code over a network.",
      "datePublished": "Aug 20, 2026, 9:43:12 PM",
      "dateUpdated": "Aug 26, 2026, 11:21:07 PM",
      "baseScore": 10.0,
      "baseScoreVersion": "3.1",
      "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C",
      "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69836\n",
      "aliases": "CVE-2026-69836\nGHSA-v6wh-624g-vvmv\n",
      "assigner": "microsoft",
      "epss": 1.59,
      "exploitedSince": "Aug 21, 2026, 12:00:00 AM",
      "enisaIdProduct": [
        {
          "id": "87e6675b-2477-3dad-a736-d16e6d53d7ad",
          "product": {
            "name": "Microsoft Entra",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "-"
        }
      ],
      "enisaIdVendor": [
        {
          "id": "434c1e3b-6884-32e9-afc6-28a522367dfb",
          "vendor": {
            "name": "Microsoft"
          }
        }
      ]
    },
    {
      "id": "EUVD-2026-56655",
      "enisaUuid": "717a0f75-594a-3284-8f76-291707d1a682",
      "description": "Heap-based buffer overflow in Windows Cloud Files Mini Filter Driver allows an authorized attacker to elevate privileges locally.",
      "datePublished": "Aug 11, 2026, 5:06:09 PM",
      "dateUpdated": "Aug 26, 2026, 11:21:06 PM",
      "baseScore": 7.8,
      "baseScoreVersion": "3.1",
      "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
      "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62771\n",
      "aliases": "GHSA-fgq2-7g5m-ch5h\nCVE-2026-62771\n",
      "assigner": "microsoft",
      "epss": 0.25,
      "enisaIdProduct": [
        {
          "id": "106effd7-6ab1-3d7f-90a6-c2615193213e",
          "product": {
            "name": "Windows 11 Version 25H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26200.0 <10.0.26200.9168"
        },
        {
          "id": "115f957e-e67c-3100-a329-66c86984e4a9",
          "product": {
            "name": "Windows 10 Version 22H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.19045.0 <10.0.19045.7663"
        },
        {
          "id": "3bff5720-ce07-37ed-b3a0-17ce606e9110",
          "product": {
            "name": "Windows Server 2025",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26100.0 <10.0.26100.33296"
        },
        {
          "id": "8c51e518-2b6b-323d-9d24-a92a111778db",
          "product": {
            "name": "Windows Server 2022",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.20348.0 <10.0.20348.5499"
        },
        {
          "id": "a3a263c1-96e7-3d88-9983-b3ab9163d483",
          "product": {
            "name": "Windows 10 Version 21H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.19044.0 <10.0.19044.7663"
        },
        {
          "id": "b962029e-fd11-3906-a62a-12a2a3aa08be",
          "product": {
            "name": "Windows Server 2025 (Server Core installation)",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26100.0 <10.0.26100.33296"
        },
        {
          "id": "c795e3e0-7b70-39ed-b202-c03e5dc0f04c",
          "product": {
            "name": "Windows 11 Version 23H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.22631.0 <10.0.22631.7517"
        },
        {
          "id": "d117b5b7-6f75-39ce-b63b-72ba5439f13e",
          "product": {
            "name": "Windows Server 2019",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.17763.0 <10.0.17763.9121"
        },
        {
          "id": "d8eedfe3-7e8f-38ba-972e-d0e293b912b4",
          "product": {
            "name": "Windows 11 Version 24H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26100.0 <10.0.26100.9168"
        },
        {
          "id": "e5578556-44c0-35e7-9d45-9953603c8655",
          "product": {
            "name": "Windows 10 Version 1809",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.17763.0 <10.0.17763.9121"
        },
        {
          "id": "e5652c20-520f-36db-a16a-af8dbc62d6d3",
          "product": {
            "name": "Windows Server 2019 (Server Core installation)",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.17763.0 <10.0.17763.9121"
        },
        {
          "id": "f25d0cce-93b9-341e-afc0-a6b1d64640c9",
          "product": {
            "name": "Windows 11 version 26H1",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.28000.0 <10.0.28000.2704"
        }
      ],
      "enisaIdVendor": [
        {
          "id": "b0952085-a1cf-38e2-8cf8-6272484d4cc9",
          "vendor": {
            "name": "Microsoft"
          }
        }
      ]
    },
    {
      "id": "EUVD-2026-56638",
      "enisaUuid": "8cfae48b-88cd-33f0-9864-139a43aa8b57",
      "description": "Insufficient granularity of access control in User-Mode Power Service (UMPS) allows an authorized attacker to elevate privileges locally.",
      "datePublished": "Aug 11, 2026, 5:06:00 PM",
      "dateUpdated": "Aug 26, 2026, 11:21:05 PM",
      "baseScore": 7.8,
      "baseScoreVersion": "3.1",
      "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
      "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62721\n",
      "aliases": "GHSA-2rpv-2fr2-r2m9\nCVE-2026-62721\n",
      "assigner": "microsoft",
      "epss": 0.38,
      "enisaIdProduct": [
        {
          "id": "03db02bf-7c84-3daf-aab7-b34ab926fb88",
          "product": {
            "name": "Windows Server 2019",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.17763.0 <10.0.17763.9121"
        },
        {
          "id": "0a351f06-f17a-3284-aa22-ab56a095aaae",
          "product": {
            "name": "Windows Server 2012 R2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "6.3.9600.0 <6.3.9600.23338"
        },
        {
          "id": "173342dc-07d7-3d83-9949-dc88ccd8f265",
          "product": {
            "name": "Windows 10 Version 1809",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.17763.0 <10.0.17763.9121"
        },
        {
          "id": "17ea03cc-3aa8-3242-9530-0c88c4b6b87b",
          "product": {
            "name": "Windows 10 Version 21H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.19044.0 <10.0.19044.7663"
        },
        {
          "id": "1983e7e5-ed9b-3905-ab0a-6c1ec24fe239",
          "product": {
            "name": "Windows Server 2016 (Server Core installation)",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.14393.0 <10.0.14393.9418"
        },
        {
          "id": "24fc2be4-1a27-309c-bed5-f0954cf636dc",
          "product": {
            "name": "Windows 11 version 26H1",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.28000.0 <10.0.28000.2704"
        },
        {
          "id": "2c6e947a-c660-3f17-9158-86d6bed81003",
          "product": {
            "name": "Windows Server 2025",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26100.0 <10.0.26100.33296"
        },
        {
          "id": "48fc0c85-d478-3756-9422-d148a9eac776",
          "product": {
            "name": "Windows 11 Version 23H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.22631.0 <10.0.22631.7517"
        },
        {
          "id": "529a2a8b-e466-34d6-9515-74c8dca3fd3d",
          "product": {
            "name": "Windows 11 Version 25H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26200.0 <10.0.26200.9168"
        },
        {
          "id": "56c1e64b-0deb-366e-bff9-55e9a25b0efe",
          "product": {
            "name": "Windows Server 2012 R2 (Server Core installation)",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "6.3.9600.0 <6.3.9600.23338"
        },
        {
          "id": "6a75e008-7e40-35d0-8c39-fedcfafa68dd",
          "product": {
            "name": "Windows 10 Version 1607",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.14393.0 <10.0.14393.9418"
        },
        {
          "id": "76f13c0b-7ca2-3ae8-905a-44a29859c885",
          "product": {
            "name": "Windows Server 2012",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "6.2.9200.0 <6.2.9200.26280"
        },
        {
          "id": "7bf40cbf-6d23-303c-8434-bd652c3bd09a",
          "product": {
            "name": "Windows Server 2019 (Server Core installation)",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.17763.0 <10.0.17763.9121"
        },
        {
          "id": "9cbd11e6-7b5f-37fc-b5a6-ea123e47d5d5",
          "product": {
            "name": "Windows 11 Version 24H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26100.0 <10.0.26100.9168"
        },
        {
          "id": "c233bf34-6e18-3de5-977d-449754bdf2c0",
          "product": {
            "name": "Windows Server 2025 (Server Core installation)",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.26100.0 <10.0.26100.33296"
        },
        {
          "id": "c593e46f-dbb1-3134-a2ea-79e7cf45387b",
          "product": {
            "name": "Windows Server 2016",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.14393.0 <10.0.14393.9418"
        },
        {
          "id": "df45071d-a0f9-3cdf-be33-37d1beca1ed3",
          "product": {
            "name": "Windows Server 2022",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.20348.0 <10.0.20348.5499"
        },
        {
          "id": "f1fc9b1b-2563-3455-a5d8-5ada51a8e800",
          "product": {
            "name": "Windows Server 2012 (Server Core installation)",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "6.2.9200.0 <6.2.9200.26280"
        },
        {
          "id": "fd012e4d-a8e9-3e1b-b0dc-987850999dfe",
          "product": {
            "name": "Windows 10 Version 22H2",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "10.0.19045.0 <10.0.19045.7663"
        }
      ],
      "enisaIdVendor": [
        {
          "id": "342a289c-0ca6-311d-9a1a-568844375d67",
          "vendor": {
            "name": "Microsoft"
          }
        }
      ]
    },
    {
      "id": "EUVD-2026-56588",
      "enisaUuid": "36451781-dfb9-3b06-84c6-12265750028e",
      "description": "Improper neutralization of special elements used in an os command ('os command injection') in GitHub Copilot and Visual Studio Code allows an unauthorized attacker to elevate privileges locally.",
      "datePublished": "Aug 11, 2026, 5:05:32 PM",
      "dateUpdated": "Aug 26, 2026, 11:21:05 PM",
      "baseScore": 7.8,
      "baseScoreVersion": "3.1",
      "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
      "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70335\n",
      "aliases": "CVE-2026-70335\nGHSA-hj52-q5wj-vpwg\n",
      "assigner": "microsoft",
      "epss": 0.42,
      "enisaIdProduct": [
        {
          "id": "587750d1-f1dd-39fe-8ffb-41ac65e51bb4",
          "product": {
            "name": "Visual Studio Code",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "1.0.0 <1.132.1"
        }
      ],
      "enisaIdVendor": [
        {
          "id": "e8e1aa20-3043-30d8-aaab-6b94f0b738ae",
          "vendor": {
            "name": "Microsoft"
          }
        }
      ]
    },
    {
      "id": "EUVD-2026-56756",
      "enisaUuid": "91c3049e-f986-3e9f-acea-faa0a05d9130",
      "description": "Heap-based buffer overflow in Microsoft Office Excel allows an unauthorized attacker to execute code locally.",
      "datePublished": "Aug 11, 2026, 5:07:06 PM",
      "dateUpdated": "Aug 26, 2026, 11:21:03 PM",
      "baseScore": 7.8,
      "baseScoreVersion": "3.1",
      "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
      "references": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68801\n",
      "aliases": "GHSA-cff6-wjc9-gpcj\nCVE-2026-68801\n",
      "assigner": "microsoft",
      "epss": 0.33,
      "enisaIdProduct": [
        {
          "id": "195a3dab-8b72-3e9a-8abc-b4b8a8587f37",
          "product": {
            "name": "Microsoft Office LTSC for Mac 2021",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "16.0.1 <16.112.26081010"
        },
        {
          "id": "3cec4b36-20b8-3f52-a506-6eecc33e8052",
          "product": {
            "name": "Microsoft Excel 2016",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "16.0.0.0 <16.0.5565.1001"
        },
        {
          "id": "42deb772-23c4-3a42-b16d-450ac6b8cd3f",
          "product": {
            "name": "Microsoft Office 2019",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "19.0.0 <https://aka.ms/OfficeSecurityReleases"
        },
        {
          "id": "4506466c-e705-377a-802d-4bdf5a9be53f",
          "product": {
            "name": "Microsoft Office 365 for Mac",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "1.0.0 <16.112.26081010"
        },
        {
          "id": "7714c804-67a2-3b9b-810c-59db6da63b61",
          "product": {
            "name": "Microsoft Office LTSC 2021",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "16.0.1 <https://aka.ms/OfficeSecurityReleases"
        },
        {
          "id": "7b35c6d2-a3ff-3ff8-bac3-97efab3a0b0b",
          "product": {
            "name": "Microsoft 365 Apps for Enterprise",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "16.0.1 <https://aka.ms/OfficeSecurityReleases"
        },
        {
          "id": "84b34faf-6928-30a0-afb7-dfedb20fddc0",
          "product": {
            "name": "Office Online Server",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "16.0.0.0 <16.0.10417.20175"
        },
        {
          "id": "c6943a7a-f99b-3681-a14d-b1179bbf10f0",
          "product": {
            "name": "Microsoft Office LTSC 2024",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "16.0.0 <https://aka.ms/OfficeSecurityReleases"
        },
        {
          "id": "f705d0e7-928d-3c51-981b-382330c6c61d",
          "product": {
            "name": "Microsoft Office LTSC for Mac 2024",
            "vendor": {
              "name": "Microsoft"
            }
          },
          "product_version": "16.0.0 <16.112.26081010"
        }
      ],
      "enisaIdVendor": [
        {
          "id": "076ca8b7-2161-34f6-a0af-c07b9d015923",
          "vendor": {
            "name": "Microsoft"
          }
        }
      ]
    }
  ],
  "total": 79121
}
```


## Specific Resources

### Show EUVD by ID

api/enisaid?id=EUVD-2024-45012

```json
{
  "id": "EUVD-2024-45012",
  "enisaUuid": "3682114c-5225-37d7-86d3-ee75e9181d35",
  "description": "A SQL Injection was found in /admin/admin_user.php in kashipara E-learning Management System Project 1.0 via the username and password parameters.",
  "datePublished": "Nov 14, 2024, 12:00:00 AM",
  "dateUpdated": "Nov 15, 2024, 7:18:35 PM",
  "baseScore": 3.5,
  "baseScoreVersion": "3.1",
  "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
  "references": "https://github.com/m14r41/Writeups/blob/main/CVE/Kashipara/SQL%20Injection%20-%20admin%20user.pdf\n",
  "aliases": "CVE-2024-50831\nGHSA-crm2-5cww-28rj\n",
  "assigner": "mitre",
  "epss": 0.38,
  "enisaIdProduct": [
    {
      "id": "6559b1bb-acb1-38a7-a753-49cfa5c2aa79",
      "product": {
        "name": "n/a",
        "vendor": {
          "name": "n/a"
        }
      },
      "product_version": "n/a"
    }
  ],
  "enisaIdVendor": [
    {
      "id": "7fc6ff25-463c-357e-ac34-3e7261566f5c",
      "vendor": {
        "name": "n/a"
      }
    }
  ],
  "enisaIdVulnerability": [
    {
      "id": "57915f5f-7d03-3fcb-81bc-405a219762f6",
      "vulnerability": {
        "id": "GHSA-crm2-5cww-28rj",
        "description": "A SQL Injection was found in /admin/admin_user.php in kashipara E-learning Management System Project 1.0 via the username and password parameters.",
        "datePublished": "Nov 14, 2024, 6:30:38 PM",
        "dateUpdated": "Nov 15, 2024, 9:30:46 PM",
        "baseScore": 0.0,
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2024-50831\nhttps://github.com/m14r41/Writeups/blob/main/CVE/Kashipara/SQL%20Injection%20-%20admin%20user.pdf\n",
        "enisa_id": "EUVD-2024-45012\n",
        "aliases": "GHSA-crm2-5cww-28rj\nCVE-2024-50831\n",
        "epss": 0.0,
        "dataProcessed": "May 3, 2026, 2:10:21 AM",
        "vulnerabilityProduct": [],
        "vulnerabilityVendor": []
      }
    },
    {
      "id": "ab7bf03b-77bd-3f2f-bd2b-5ce17d5262d6",
      "vulnerability": {
        "id": "CVE-2024-50831",
        "description": "A SQL Injection was found in /admin/admin_user.php in kashipara E-learning Management System Project 1.0 via the username and password parameters.",
        "datePublished": "Nov 14, 2024, 12:00:00 AM",
        "dateUpdated": "Nov 15, 2024, 7:18:35 PM",
        "status": "PUBLISHED",
        "baseScore": 3.5,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
        "references": "https://github.com/m14r41/Writeups/blob/main/CVE/Kashipara/SQL%20Injection%20-%20admin%20user.pdf\n",
        "enisa_id": "EUVD-2024-45012\n",
        "assigner": "mitre",
        "epss": 0.38,
        "dataProcessed": "Aug 26, 2026, 7:09:24 AM",
        "vulnerabilityProduct": [
          {
            "id": "c799a1dd-abd7-3515-a8be-ae3b92cdcf7e",
            "product": {
              "name": "n/a",
              "vendor": {
                "name": "n/a"
              }
            },
            "product_version": "n/a"
          }
        ],
        "vulnerabilityVendor": [
          {
            "id": "0444d96e-4f78-3efa-a914-67d5df2c50fb",
            "vendor": {
              "name": "n/a"
            }
          }
        ]
      }
    }
  ],
  "enisaIdAdvisory": []
}
```

### Show advisory by ID

api/advisory?id=cisco-sa-ata19x-multi-RDTEqRsy

```json
{
  "id": "cisco-sa-ata19x-multi-RDTEqRsy",
  "description": "Cisco ATA 190 Series Analog Telephone Adapter Firmware Vulnerabilities",
  "summary": "Multiple vulnerabilities in Cisco ATA 190 Series Analog Telephone Adapter firmware, both on-premises and multiplatform, could allow a remote attacker to delete or change the configuration, execute commands as the root user, conduct a cross-site scripting (XSS) attack against a user of the interface, view passwords, conduct a cross-site request forgery (CSRF) attack, or reboot the device.\r\n\r\nFor more information about these vulnerabilities, see the Details [\"#details\"] section of this advisory.\r\n\r\nCisco has released firmware updates that address these vulnerabilities. There are no workarounds that address these vulnerabilities. However, there is a mitigation that addresses some of these vulnerabilities for Cisco ATA 191 on-premises firmware only.\r\n\r\n",
  "datePublished": "Oct 16, 2024, 4:00:00 PM",
  "dateUpdated": "Oct 24, 2024, 11:47:37 AM",
  "baseScore": 0.0,
  "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
  "aliases": "CVE-2024-20420\nCVE-2024-20459\nCVE-2024-20460\nCVE-2024-20421\nCVE-2024-20463\nCVE-2024-20458\nCVE-2024-20462\nCVE-2024-20461\n",
  "source": {
    "id": 10,
    "name": "csaf_cisco"
  },
  "advisoryProduct": [
    {
      "id": "5fe32ac4-e2d7-36d8-93f5-df5dde4f4a9a",
      "product": {
        "name": "Cisco Analog Telephone Adaptor (ATA) Software",
        "vendor": {
          "name": "Cisco"
        }
      }
    }
  ],
  "enisaIdAdvisories": [
    {
      "id": "129758d0-efa1-3f4f-b23f-4a0f2de21a93",
      "enisaId": {
        "id": "EUVD-2024-18178",
        "enisaUuid": "c529d49e-e7df-3d07-a565-af3731b29241",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to modify the configuration or reboot an affected device.\r\n\r\nThis vulnerability is due to the HTTP server allowing state changes in GET requests. An attacker could exploit this vulnerability by sending a malicious request to the web-based management interface on an affected device. A successful exploit could allow the attacker to make limited modifications to the configuration or reboot the device, resulting in a denial of service (DoS) condition.&nbsp;",
        "datePublished": "Oct 16, 2024, 4:16:53 PM",
        "dateUpdated": "Oct 31, 2024, 1:08:14 PM",
        "baseScore": 5.4,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20463\nGHSA-8vcm-p6g6-xjqp\n",
        "assigner": "cisco",
        "epss": 0.36,
        "enisaIdVendor": [
          {
            "id": "40bd26b4-ff0b-3a65-a207-2aa2f5490e46",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "2a06bc1a-1ac2-3ec3-88ab-d9a62d5c6b6b",
      "enisaId": {
        "id": "EUVD-2024-18135",
        "enisaUuid": "0765a029-d47e-34c6-b994-8accdc46fb76",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an authenticated, remote attacker with low privileges to run commands as an Admin user. \r\n\r\nThis vulnerability is due to incorrect authorization verification by the HTTP server. An attacker could exploit this vulnerability by sending a malicious request to the web-based management interface. A successful exploit could allow the attacker to run commands as the Admin user.",
        "datePublished": "Oct 16, 2024, 4:15:45 PM",
        "dateUpdated": "Oct 31, 2024, 1:12:38 PM",
        "baseScore": 5.4,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20420\nGHSA-w5cm-m7c3-4jj4\n",
        "assigner": "cisco",
        "epss": 0.36,
        "enisaIdVendor": [
          {
            "id": "20b816ba-1e0a-33f8-9651-c6085d020a10",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "8820ad84-4029-3c96-a142-8b386e6ab2eb",
      "enisaId": {
        "id": "EUVD-2024-18174",
        "enisaUuid": "e4358962-66a9-32a8-82c2-3a6cb2d4b832",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Multiplatform Series Analog Telephone Adapter firmware could allow an authenticated, remote attacker with high privileges to execute arbitrary commands as the root user on the underlying operating system.\r\n\r\nThis vulnerability is due to a lack of input sanitization in the web-based management interface. An attacker could exploit this vulnerability by sending a malicious request to the web-based management interface. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system as the root user.",
        "datePublished": "Oct 16, 2024, 4:16:12 PM",
        "dateUpdated": "Oct 16, 2024, 5:56:02 PM",
        "baseScore": 6.5,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20459\nGHSA-vg6p-xhm4-6r5f\n",
        "assigner": "cisco",
        "epss": 0.67,
        "enisaIdVendor": [
          {
            "id": "269948fa-490a-3f87-8bfc-5f76a103ce1d",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "a7226346-69e1-3ad2-9497-0b8044ffe774",
      "enisaId": {
        "id": "EUVD-2024-18173",
        "enisaUuid": "fa3c3589-ffb2-39a0-82cf-2750421eebdb",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to view or delete the configuration or change the firmware on an affected device.\r\n\r\nThis vulnerability is due to a lack of authentication on specific HTTP endpoints. An attacker could exploit this vulnerability by browsing to a specific URL. A successful exploit could allow the attacker to view or delete the configuration or change the firmware.",
        "datePublished": "Oct 16, 2024, 4:16:04 PM",
        "dateUpdated": "Oct 16, 2024, 7:38:32 PM",
        "baseScore": 8.2,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20458\nGHSA-3v49-pp4c-p3j5\n",
        "assigner": "cisco",
        "epss": 0.71,
        "enisaIdVendor": [
          {
            "id": "ded05373-e23c-35ba-8a47-fb0d8e246800",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "b050e851-091e-326a-a285-fdf043d2093f",
      "enisaId": {
        "id": "EUVD-2024-18176",
        "enisaUuid": "112b603f-432b-3fd5-96d7-c4cbb49b22a1",
        "description": "A vulnerability in the CLI&nbsp;of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an authenticated, local attacker with high privileges to execute arbitrary commands as the root user.\r\n\r\nThis vulnerability exists because CLI input is not properly sanitized. An attacker could exploit this vulnerability by sending malicious characters to the CLI. A successful exploit could allow the attacker to read and write to the underlying operating system as the root user.",
        "datePublished": "Oct 16, 2024, 4:16:34 PM",
        "dateUpdated": "Oct 16, 2024, 7:39:07 PM",
        "baseScore": 6.0,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20461\nGHSA-98h2-2cpv-4fq9\n",
        "assigner": "cisco",
        "epss": 0.18,
        "enisaIdVendor": [
          {
            "id": "0b0acc45-a727-3c1d-bf4f-599137a6367b",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "c626a171-4188-36c2-9859-da31dec5f01f",
      "enisaId": {
        "id": "EUVD-2024-18136",
        "enisaUuid": "f4fc6431-0f97-3df9-ad90-e559d1f9cfa8",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected device.\r\n\r\nThis vulnerability is due to insufficient CSRF protections for the web-based management interface of an affected device. An attacker could exploit this vulnerability by persuading a user to follow a crafted link. A successful exploit could allow the attacker to perform arbitrary actions on the affected device with the privileges of the targeted user.",
        "datePublished": "Oct 16, 2024, 4:15:54 PM",
        "dateUpdated": "Oct 31, 2024, 1:49:46 PM",
        "baseScore": 7.1,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20421\nGHSA-q72g-w9rr-ph62\n",
        "assigner": "cisco",
        "epss": 0.23,
        "enisaIdVendor": [
          {
            "id": "6c4ce124-0c04-3178-99c3-c4b16e37b8e0",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "cf574381-c186-3cca-bf0b-5c65e51fc6e9",
      "enisaId": {
        "id": "EUVD-2024-18175",
        "enisaUuid": "f286fbc0-1a03-3c7b-8480-1ee4a33e5532",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to conduct a reflected cross-site scripting (XSS) attack against a user.\r\n\r\nThis vulnerability is due to insufficient validation of user input. An attacker could exploit this vulnerability by persuading a user&nbsp;to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive, browser-based information on an affected device.",
        "datePublished": "Oct 16, 2024, 4:16:23 PM",
        "dateUpdated": "Oct 31, 2024, 2:10:45 PM",
        "baseScore": 6.1,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20460\nGHSA-p7rx-j8x8-2j2p\n",
        "assigner": "cisco",
        "epss": 0.32,
        "enisaIdVendor": [
          {
            "id": "4b208cfd-7a4a-3538-89b1-9cb69c401c68",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "d0d56cf9-dbf7-31f5-9c96-df95f5c8efc3",
      "enisaId": {
        "id": "EUVD-2024-18177",
        "enisaUuid": "e783216f-2abe-33b7-82fc-7c64c0ec9a24",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Multiplatform Analog Telephone Adapter firmware could allow an authenticated, local attacker with low privileges to view passwords on an affected device.\r\n\r\nThis vulnerability is due to incorrect sanitization of HTML content from an affected device. A successful exploit could allow the attacker to view passwords that belong to other users.",
        "datePublished": "Oct 16, 2024, 4:16:44 PM",
        "dateUpdated": "Oct 31, 2024, 1:17:38 PM",
        "baseScore": 5.5,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "aliases": "CVE-2024-20462\nGHSA-j4rf-24v6-vq7x\n",
        "assigner": "cisco",
        "epss": 0.16,
        "enisaIdVendor": [
          {
            "id": "0921077e-bf8e-388f-93fc-e677bd02e8ae",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    }
  ],
  "vulnerabilityAdvisory": [
    {
      "id": "63ee6b0c-b082-3fd7-b48c-974cff2a406f",
      "vulnerability": {
        "id": "CVE-2024-20420",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an authenticated, remote attacker with low privileges to run commands as an Admin user. \r\n\r\nThis vulnerability is due to incorrect authorization verification by the HTTP server. An attacker could exploit this vulnerability by sending a malicious request to the web-based management interface. A successful exploit could allow the attacker to run commands as the Admin user.",
        "datePublished": "Oct 16, 2024, 4:15:45 PM",
        "dateUpdated": "Oct 31, 2024, 1:12:38 PM",
        "status": "PUBLISHED",
        "baseScore": 5.4,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18135\n",
        "assigner": "cisco",
        "epss": 0.36,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "5d2d17dc-a5bc-3e1e-9d97-493b840b625d",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "7a503bec-e7a3-3624-baaf-193cf775ffd0",
      "vulnerability": {
        "id": "CVE-2024-20461",
        "description": "A vulnerability in the CLI&nbsp;of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an authenticated, local attacker with high privileges to execute arbitrary commands as the root user.\r\n\r\nThis vulnerability exists because CLI input is not properly sanitized. An attacker could exploit this vulnerability by sending malicious characters to the CLI. A successful exploit could allow the attacker to read and write to the underlying operating system as the root user.",
        "datePublished": "Oct 16, 2024, 4:16:34 PM",
        "dateUpdated": "Oct 16, 2024, 7:39:07 PM",
        "status": "PUBLISHED",
        "baseScore": 6.0,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18176\n",
        "assigner": "cisco",
        "epss": 0.18,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "6bc17203-e7c5-3f37-a3de-6194d86cd9c2",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "7d6d1245-7d47-36a8-a8ba-1cd259d58b69",
      "vulnerability": {
        "id": "CVE-2024-20459",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Multiplatform Series Analog Telephone Adapter firmware could allow an authenticated, remote attacker with high privileges to execute arbitrary commands as the root user on the underlying operating system.\r\n\r\nThis vulnerability is due to a lack of input sanitization in the web-based management interface. An attacker could exploit this vulnerability by sending a malicious request to the web-based management interface. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system as the root user.",
        "datePublished": "Oct 16, 2024, 4:16:12 PM",
        "dateUpdated": "Oct 16, 2024, 5:56:02 PM",
        "status": "PUBLISHED",
        "baseScore": 6.5,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18174\n",
        "assigner": "cisco",
        "epss": 0.67,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "7164aa6d-ac6d-39d9-a07c-b5b3f181824d",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "884c695d-73fd-3cb2-a122-6f4fc3d7acf8",
      "vulnerability": {
        "id": "CVE-2024-20421",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected device.\r\n\r\nThis vulnerability is due to insufficient CSRF protections for the web-based management interface of an affected device. An attacker could exploit this vulnerability by persuading a user to follow a crafted link. A successful exploit could allow the attacker to perform arbitrary actions on the affected device with the privileges of the targeted user.",
        "datePublished": "Oct 16, 2024, 4:15:54 PM",
        "dateUpdated": "Oct 31, 2024, 1:49:46 PM",
        "status": "PUBLISHED",
        "baseScore": 7.1,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18136\n",
        "assigner": "cisco",
        "epss": 0.23,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "b82d9e49-fea5-3d11-8779-6d5404d1e727",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "966a2969-6658-3bb5-a6b7-8b1c606addaf",
      "vulnerability": {
        "id": "CVE-2024-20462",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Multiplatform Analog Telephone Adapter firmware could allow an authenticated, local attacker with low privileges to view passwords on an affected device.\r\n\r\nThis vulnerability is due to incorrect sanitization of HTML content from an affected device. A successful exploit could allow the attacker to view passwords that belong to other users.",
        "datePublished": "Oct 16, 2024, 4:16:44 PM",
        "dateUpdated": "Oct 31, 2024, 1:17:38 PM",
        "status": "PUBLISHED",
        "baseScore": 5.5,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18177\n",
        "assigner": "cisco",
        "epss": 0.16,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "0e978224-181a-3ba3-ae4a-88f2af126f65",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "a1a0e7cb-99a7-3f27-af37-68337e56b22b",
      "vulnerability": {
        "id": "CVE-2024-20460",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to conduct a reflected cross-site scripting (XSS) attack against a user.\r\n\r\nThis vulnerability is due to insufficient validation of user input. An attacker could exploit this vulnerability by persuading a user&nbsp;to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive, browser-based information on an affected device.",
        "datePublished": "Oct 16, 2024, 4:16:23 PM",
        "dateUpdated": "Oct 31, 2024, 2:10:45 PM",
        "status": "PUBLISHED",
        "baseScore": 6.1,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18175\n",
        "assigner": "cisco",
        "epss": 0.32,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "926ba021-503b-3cd2-88e3-5a0c06724163",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "b8f9e788-85a9-3cac-8670-ce983b0a7cd0",
      "vulnerability": {
        "id": "CVE-2024-20458",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to view or delete the configuration or change the firmware on an affected device.\r\n\r\nThis vulnerability is due to a lack of authentication on specific HTTP endpoints. An attacker could exploit this vulnerability by browsing to a specific URL. A successful exploit could allow the attacker to view or delete the configuration or change the firmware.",
        "datePublished": "Oct 16, 2024, 4:16:04 PM",
        "dateUpdated": "Oct 16, 2024, 7:38:32 PM",
        "status": "PUBLISHED",
        "baseScore": 8.2,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18173\n",
        "assigner": "cisco",
        "epss": 0.71,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "c85e242f-00d9-3364-8965-9c415c1ca840",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    },
    {
      "id": "c4aa5a7b-5f2b-3a96-9d6b-fb5feb5d7549",
      "vulnerability": {
        "id": "CVE-2024-20463",
        "description": "A vulnerability in the web-based management interface of Cisco ATA 190 Series Analog Telephone Adapter firmware could allow an unauthenticated, remote attacker to modify the configuration or reboot an affected device.\r\n\r\nThis vulnerability is due to the HTTP server allowing state changes in GET requests. An attacker could exploit this vulnerability by sending a malicious request to the web-based management interface on an affected device. A successful exploit could allow the attacker to make limited modifications to the configuration or reboot the device, resulting in a denial of service (DoS) condition.&nbsp;",
        "datePublished": "Oct 16, 2024, 4:16:53 PM",
        "dateUpdated": "Oct 31, 2024, 1:08:14 PM",
        "status": "PUBLISHED",
        "baseScore": 5.4,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ata19x-multi-RDTEqRsy\n",
        "enisa_id": "EUVD-2024-18178\n",
        "assigner": "cisco",
        "epss": 0.36,
        "dataProcessed": "Aug 26, 2026, 7:14:01 AM",
        "vulnerabilityVendor": [
          {
            "id": "c104278d-cb59-3fd1-b8df-8f970eb07042",
            "vendor": {
              "name": "Cisco"
            }
          }
        ]
      }
    }
  ]
}
```

## Data Downloads

### Download CVE-to-EUVD ID Mapping (CSV)

api/dump/cve-euvd-mapping

```csv
euvd_id,cve_id
EUVD-1999-0001,CVE-1999-0001
EUVD-1999-0002,CVE-1999-0002
EUVD-1999-0003,CVE-1999-0003
...
EUVD-2026-9996,CVE-2026-28787
EUVD-2026-9997,CVE-2026-28794
EUVD-2026-9998,CVE-2026-29060
EUVD-2026-9999,CVE-2026-29061
```

### Download KEV Dump (JSON)

api/kev/dump

```json
[
  {
    "cveId": "CVE-2021-22555",
    "euvdId": "EUVD-2021-9696",
    "dateAdded": "2025-10-06",
    "sources": [
      "cisa_kev"
    ]
  },
  {
    "cveId": "CVE-2024-38856",
    "euvdId": "EUVD-2024-37643",
    "dateAdded": "2024-08-27",
    "sources": [
      "cisa_kev"
    ]
  },
  {
    "cveId": "CVE-2021-21220",
    "euvdId": "EUVD-2021-8611",
    "dateAdded": "2021-11-03",
    "sources": [
      "cisa_kev"
    ]
  },
  ...
  {
    "cveId": "CVE-2026-21962",
    "euvdId": "EUVD-2026-3550",
    "dateAdded": "2026-08-24",
    "sources": [
      "cisa_kev"
    ]
  }
```