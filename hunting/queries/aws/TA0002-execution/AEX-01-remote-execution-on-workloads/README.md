# AEX-01 Code run on workloads through AWS APIs: SSM, EC2 user data, Instance Connect, Lambda, ECS, CloudFormation

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1651 Cloud Administration Command, T1059.009 Cloud API, T1648 Serverless Execution |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management events |
| Applies to | every AWS account with EC2, Lambda or ECS workloads |

**What it finds.** Every API call that runs code or opens a shell on a workload: SSM Run Command and Session Manager, EC2 user data set at launch or changed later, EC2 Instance Connect and serial-console keys pushed, Lambda code deployments, configuration changes and new invoke permissions or function URLs, ECS exec and tasks, CloudFormation stacks, CodeBuild builds.

**Reading the output.** Know the client's automation first: deployment pipelines create most of these rows, from the same role and user agent every time. What stands out is a human principal (an IAM user or an SSO session) or an unfamiliar role running `SendCommand` with `AWS-RunShellScript`/`AWS-RunPowerShellScript`, changing user data on a stopped instance (it runs at the next boot), or adding a public function URL. SSM command text is redacted in CloudTrail (`HIDDEN_DUE_TO_SECURITY_REASONS`); get it from the SSM command history or the instance itself.

**If it errors or looks empty.** `request` is cut to 600 characters; the full JSON is in `aws.cloudtrail.flattened.request_parameters`. Lambda `Invoke` is a data event and only appears if the trail logs Lambda data events.
