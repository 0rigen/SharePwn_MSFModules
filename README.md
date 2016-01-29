# SharePwn_MSFModules
Metasploit modules to perform SharePoint misconfiguration exploitation.

This repo is in-progress and will be updated piecemeal, as modules are created.
Nothing here is final or has undergone more than cursory testing.

* sharepoint_brute_browse - Brute-Froce browser that attempts to locate common/default SharePoint pages, services, etc.

* sharepoint_people_enumeration - [IN-DEVELOPMENT] Leverages the People.asmx service to enumerate intenral systems and accounts
(This is based on experience during previous engagements, when, with a valid account or misconfigured service, we were able to enumerate system names, network accounts, built-in accounts, etc that were not SP users, but exist in AD.)

* sharepoint_version_id - Identifies the Sharepoint Version, Health Score, and other software version information on the server


