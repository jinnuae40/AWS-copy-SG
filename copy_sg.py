import boto3

src_sg_list = [""]  # sg-XXXX
dst_sg_list = [""]  # sg-XXXX
src_region = ""  # ap-northeast-2
dst_region = ""  # ap-northeast-1

src_client = boto3.client('ec2', region_name=src_region)
dst_client = boto3.client('ec2', region_name=dst_region)


def get_ip_permissions(option):
    ip_permissions = []
    print('Protocol\tSrcPort\t\tToPort\t\tCidr\t\tDescription')
    for permission in src_sg_details['SecurityGroups'][0][option]:
        for ip_range in permission['IpRanges']:
            cidr = ip_range['CidrIp']
            from_port = permission['FromPort'] if 'FromPort' in permission else -1
            to_port = permission['ToPort'] if 'ToPort' in permission else -1
            protocol = permission['IpProtocol'] if 'IpProtocol' in permission else ''
            description = ip_range['Description'] if 'Description' in ip_range else ''
            print(
                f'{protocol}\t\t{from_port}\t\t{to_port}\t\t{cidr}\t\t{description}')
            item = {'IpRanges': [{'CidrIp': cidr, 'Description': description}],
                    'FromPort': from_port, 'IpProtocol': protocol, 'ToPort': to_port}
            ip_permissions.append(item)
    return ip_permissions


def copy_sg(src_sg_details, option):
    ip_permissions = get_ip_permissions(option)
    try:
        if 'Egress' in option:
            dst_client.authorize_security_group_egress(
                GroupId=dst_sg, IpPermissions=ip_permissions)
        else:
            dst_client.authorize_security_group_ingress(
                GroupId=dst_sg, IpPermissions=ip_permissions)

    except Exception as e:
        print(e)


if __name__ == "__main__":
    for i in range(0, len(src_sg_list)):
        src_sg = src_sg_list[i]
        dst_sg = dst_sg_list[i]

        src_sg_details = src_client.describe_security_groups(GroupIds=[src_sg])
        print(f'Copy {src_sg} to {dst_sg}')
        print()
        print(f'(Ingress)')
        copy_sg(src_sg_details, 'IpPermissions')
        print()
        print(f'(Engress)')
        copy_sg(src_sg_details, 'IpPermissionsEgress')
