# sap-pi-custom-modules
SAP PI custom modules examples

### custom.modules.jpa (JPA util project for exposing DB operations)
- SFLoginBean
  * Access to Salesforce sessions login cache custom table.

### custom.modules (custom modules ejb and ear projects)

- SalesForceAxisLoginCacheModule (jndi: CustomModules/NMSC/SalesForceAxisLoginCacheModule)
  * Axis module that fetches and stores a session token from Salesforce (from an already created PI channel). Also sets a dynamic target url using axis module. Check code for parameters (username, pwd, service, channel, fixedPath). Requires custom.modules.jpa.app deployed for DB operations.


- WSAAndCertificateExtractorModule (jndi: CustomModules/NMSC/WSAAndCertificateExtractorModule)
  * Axis module that extracts WSA elements (ReplyTo, FaultTo, MessageID) and also signature related certificates (in different forms, as in WSS4J: Binary Security Token, X509 Certificate, ...). This module also fetches the certificate from the AS Java if needed.


## Build & Deployment (without creating software and development components)

- Clone the repository and import the eclipse projects into your workspace (you can the use eclipse's EGit).
- You will have to define an user library: **SAP PI LIBS**, with XPI mapping and adapter libraries - you can find the jars in your NWDS installation folder: `plugins\com.sap.ext.libs.xpi_XXXX\DesigntimeAPIs`.
- Build all projects using maven eclipse plugin.
- Extract the ear artifacts from the app projects with no specific target runtime.
- Deploy the artifacts (first the jpa and after the modules ear) using NWDS (deployment perspective) or using SAP deploy script: `/usr/sap/<SID>/J<nr>/j2ee/deployment/scripts/deploy.bat <user>:<password>@<host>:<port> <full path to ear file>`.
