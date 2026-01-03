# Mitigation Title
Restrict Bedrock Service-Specific Credential Creation

# Description
This mitigation implements a Service Control Policy (SCP) at the AWS Organizations level to proactively deny the creation of Amazon Bedrock service-specific credentials (API keys) across member accounts, unless the request is explicitly authorized via specific resource tags or originates from an approved Organizational Unit (OU). The policy leverages the iam:CreateServiceSpecificCredential action and the iam:ServiceSpecificCredentialServiceName condition key to target only Bedrock credential creation, thereby preventing the proliferation of long-term API keys that present a higher risk profile due to their extended validity and potential for excessive permissions if not properly scoped.

# Effect
When this mitigation is enabled and a threat event occurs—such as an attacker attempting to create a persistent Amazon Bedrock API key after compromising an IAM principal with excessive privileges—the SCP will intercept the CreateServiceSpecificCredential API call. The request will be denied at the Organizations level before the credential is provisioned, effectively containing the attack by blocking the establishment of a new, potentially unauthorized, long-term authentication mechanism. The exceptions for specific tags (aws:RequestTag/CreatedBy=Automation) and approved OUs ensure continuous delivery pipelines and authorized administrative functions are not disrupted, maintaining operational resilience while enforcing security boundaries.

# Implementation
The following JSON is a declarative AWS Service Control Policy that can be attached to OUs or the root of an AWS Organization. It denies the creation of service-specific credentials for Amazon Bedrock unless the request is tagged for automation or originates from a pre-approved OU.

```
json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBedrockCredCreationWithoutApproval",
      "Effect": "Deny",
      "Action": "iam:CreateServiceSpecificCredential",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com"
        },
        "Null": {
          "aws:RequestTag/CreatedBy": "true"
        },
        "ForAllValues:StringNotEquals": {
          "aws:PrincipalOrgPaths": [
            "o-<your-organization-id>/ou-<root-id>/ou-<approved-ou-id>-*"
          ]
        }
      }
    },
    {
      "Sid": "AllowAutomationOrApprovedOU",
      "Effect": "Allow",
      "Action": "iam:CreateServiceSpecificCredential",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com"
        },
        "StringEqualsIfExists": {
          "aws:RequestTag/CreatedBy": "Automation"
        }
      }
    }
  ]
}
```

https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/