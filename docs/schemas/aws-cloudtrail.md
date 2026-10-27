# AWS CloudTrail schema (`aws-cloudtrail-*`)

Loaded by `AWS/cloudtrail2sofelk.py`; template `AWS/index_templates/index-aws-cloudtrail.json`. Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.cloudtrail`; `@timestamp` is `eventTime`.

## Fields from SOF-ELK's parser (`configfiles/6901-aws.conf`)

| CloudTrail field | Field | Type |
|---|---|---|
| `eventName` | `aws.cloudtrail.event_name` (also `event.action`) | keyword |
| `eventSource` | `aws.cloudtrail.event_source` | keyword |
| `awsRegion` | `cloud.region` | keyword |
| `sourceIPAddress` | `source.address`; `source.ip` when it is an IP address | keyword / ip |
| `requestID` | `aws.cloudtrail.request_id` | keyword |
| `eventID` | `aws.cloudtrail.shared_event_id` | keyword |
| `eventType` | `aws.cloudtrail.event_type` | keyword |
| `additionalEventData.bytesTransferredIn` / `Out` | `source.bytes` / `destination.bytes` | long |
| `userIdentity.accessKeyId` / `type` / `arn` | `aws.cloudtrail.user_identity.access_key_id` / `type` / `arn` | keyword |
| `userIdentity.userName` | `user.name` (also `aws.cloudtrail.user_identity.user_name`) | keyword |
| `userIdentity.sessionContext` | `aws.cloudtrail.user_identity.session_context` (JSON text) | keyword |
| `requestParameters.bucketName` | `aws.cloudtrail.request_parameters.bucket_name` | keyword |
| `requestParameters.Host` | `host.hostname` | keyword |
| `requestParameters.instanceType` | `aws.cloudtrail.request_parameters.instance_type` | keyword |
| `requestParameters.instancesSet.items[].instanceId` / `imageId` / `keyName` | `aws.cloudtrail.request_parameters.instance_id` / `image_id` / `key_name` | keyword (all items, not only the first) |
| `resources[].ARN` / `type` | `aws.cloudtrail.resources.arn` / `type` | keyword (all items) |
| `userAgent` | `user_agent.original` | keyword |
| `errorCode` / `errorMessage` | `aws.cloudtrail.error_code` / `error_message` | keyword |
| `requestParameters` / `responseElements` / `additionalEventData` | `aws.cloudtrail.flattened.request_parameters` / `response_elements` / `additional_eventdata` (JSON text) | keyword + `.text` |

## Added by the toolkit

| CloudTrail field | Field | Type |
|---|---|---|
| `eventVersion`, `eventCategory`, `vpcEndpointId` | `aws.cloudtrail.event_version`, `event_category`, `vpc_endpoint_id` | keyword |
| `recipientAccountId` | `aws.cloudtrail.recipient_account_id`, `cloud.account.id` | keyword |
| `readOnly`, `managementEvent` | `aws.cloudtrail.read_only`, `management_event` | boolean |
| `userIdentity.accountId` / `principalId` / `invokedBy` | `aws.cloudtrail.user_identity.account_id` / `principal_id` / `invoked_by` | keyword |
| `userIdentity.sessionContext.sessionIssuer.*` | `aws.cloudtrail.user_identity.session_issuer.type` / `arn` / `user_name` / `account_id` / `principal_id` | keyword |
| `...sessionContext.attributes.mfaAuthenticated` / `creationDate` | `aws.cloudtrail.user_identity.mfa_authenticated` / `session_created` | boolean / date |
| `...sessionContext.sourceIdentity` | `aws.cloudtrail.user_identity.source_identity` | keyword |
| `responseElements.ConsoleLogin` | `aws.cloudtrail.console_login` | keyword (`Success`/`Failure`) |
| `additionalEventData.MFAUsed` / `LoginTo` / `CredentialType` | `aws.cloudtrail.additional_eventdata.mfa_used` / `login_to` / `credential_type` | keyword |
| `tlsDetails.*` | `aws.cloudtrail.tls_details.tls_version` / `cipher_suite` / `client_provided_host_header` | keyword |
| `serviceEventDetails` | `aws.cloudtrail.flattened.service_event_details` (JSON text) | keyword |
| `resources[].accountId` | `aws.cloudtrail.resources.account_id` | keyword |
| (derived) | `event.outcome`: `failure` when `errorCode` is set or `ConsoleLogin` is `Failure`, else `success` | keyword |
| any other top-level field | `aws.cloudtrail.unmapped.<snake_case>` | keyword |

### Curated request and response parameters

Top-level scalar `requestParameters` keys copied to `aws.cloudtrail.request_parameters.<snake_case>` (keyword), so hunts can filter on them without parsing JSON: `bucketName`, `key`, `instanceType`, `instanceId` (also `instanceIds` and `instancesSet`), `imageId`, `keyName`, `userName`, `newUserName` (as `target_user_name`), `roleName`, `roleArn`, `roleSessionName`, `groupName`, `groupId`, `policyArn`, `policyName`, `name`, `trailName`, `secretId`, `keyId`, `functionName`, `snapshotId`, `attribute`, `attributeType`, `operationType`, `dBInstanceIdentifier`, `dBSnapshotIdentifier`, `detectorId`, `logGroupName`, `accessKeyId`, `status`, `principalArn`, `instanceProfileName`, `serialNumber`, `durationSeconds`, `sourceIdentity`, `externalId`, `fromPort`, `toPort`, `ipProtocol`, `vpcId`, `subnetId`, `regionName`, `documentName`, `target`, `stackName`, `cluster`, `taskDefinition`, `projectName`, `withDecryption`. `cidr_ip` collects every CIDR opened in `ipPermissions`, and `security_group_ids` every group in `groupSet`/`securityGroupIdSet`. Everything else stays searchable in `aws.cloudtrail.flattened.request_parameters`.

From `responseElements`: `aws.cloudtrail.response_elements.access_key_id` (`accessKey.accessKeyId` or `credentials.accessKeyId`), `assumed_role_arn` (`assumedRoleUser.arn`), `user_arn` (`user.arn`), `instance_id` (`instancesSet.items[].instanceId`).

## Differences from SOF-ELK's own output

- SOF-ELK keeps only the first `instancesSet` item and the first resource; the toolkit keeps all of them (the field becomes a list when there are several).
- SOF-ELK drops the session issuer, MFA flags, read-only and management flags, recipient account and TLS details; the toolkit keeps them.
- `event.outcome` and the curated parameters are new.

## CSV input

Read as described in [CSV input](aws-common.md#csv-input). CloudTrail-specific points:

- **Event history download (console).** With the `CloudTrail event` column, every field comes from the JSON in that column. Without it, only the summary columns exist: `Event ID`, `Event time`, `Event name`, `Event source`, `User name` (to `userIdentity.userName`), `AWS access key` (to `userIdentity.accessKeyId`), `AWS region`, `Source IP address`, `Error code`, `Read-only`. `Resource type` and `Resource name` go to `aws.cloudtrail.unmapped.*`. There is no session issuer, request parameters or user agent in that form, so the queries that use them return less.
- **Athena / CloudTrail Lake.** `useridentity`, `resources` and `tlsdetails` may be struct text or JSON; `requestparameters`, `responseelements`, `additionaleventdata` and `serviceeventdetails` are JSON text and are decoded, keeping the API's own key names.
- **Flattened exports.** Dotted columns (`userIdentity.sessionContext.sessionIssuer.userName`, `requestParameters.bucketName`) are rebuilt into the nested record.
