# sap-pi-custom-modules
SAP PI custom modules examples

### custom.modules.jpa (JPA util project for exposing DB operations)
- SFLoginBean
  * Access to Salesforce sessions login cache custom table.

### custom.modules (custom modules ejb and ear projects)

- SalesForceAxisLoginCacheModule
  * Fetches and stores a session token from Salesforce (from an already created PI channel). Also sets a dynamic target url using axis module. Check code for parameters (username, pwd, service, channel, fixedPath). Requires custom.modules.jpa.app deployed for DB operations.
