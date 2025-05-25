# ECC Tech

ECC App
 
### !! IMPORTANT
- This is internal code to be used by a known group of users.
- It is not production ready to the point where it can be used by unknown users.
- With that in mind, this code favours understandability and auditibility over maintainablity - given such a small code base.
- Eastern Cardano Council has used this app to vote on all governance/info actions to date without issue.
- Orchestrator role uses cardano-cli and Orchestrator (IOG created) CLI tools.
- Voter risk of key loss is mitigated to acceptable level by 1 of many in case of compromise and human-in-the-pool (orchestrator) protection. 

## ROADMAP
- Converge the Vote and View Transaction Data tabs so user can view and then vote with the .json file and not need the .hash file.
- When creating X509 based identity, merge in the encrypted backup, so not a separate user step.
