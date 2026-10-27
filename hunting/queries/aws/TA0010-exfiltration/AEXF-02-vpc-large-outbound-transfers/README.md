# AEXF-02 Large outbound transfers from the VPC to public addresses

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1048 Exfiltration Over Alternative Protocol, T1041 Exfiltration Over C2 Channel |
| Indexes | `aws-vpcflow-*` |
| Needs | VPC Flow Logs (accepted traffic) |
| Applies to | every VPC with flow logs |

**What it finds.** Private sources that sent 100 MB or more to a single public address, with the ports used, the AWS service the destination belongs to (when the flow log format includes `pkt-dst-aws-service`), and how many internal hosts sent that much to the same destination.

**Reading the output.** Traffic to S3, ECR and other AWS endpoints over the internet gateway is normal and shows `aws_services`; if the format has no such field, compare `destination.ip` with the published AWS ranges. A destination that only one instance sends large volumes to (`internal_peers` of 1), on an unusual port or at night, is the lead. `bytes_out` counts only the source-to-destination direction of each flow record.

**Next.** [AC2-01](../../TA0011-command-and-control/AC2-01-vpc-beaconing/) for regular, small connections to the same destination before the transfer.
