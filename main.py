import argparse
import boto3
import subprocess

from botocore.exceptions import ClientError
from config import conf

parser = argparse.ArgumentParser(description="Add or Remove public ip from SG", usage="python3 main.py --add/--remove")
parser.add_argument('--add', help="For IP add", action="store_true")
parser.add_argument('--remove', help="For IP remove", action="store_true")
args = parser.parse_args()

def getCurIpv4():
    ipAddr = subprocess.check_output(['curl', 'ifconfig.io'], stderr=subprocess.DEVNULL)
    ipv4 = ipAddr.decode('utf-8').strip()
    return ipv4

def getExisitingIPList(ingressList, desc):
    import re
    
    descLower = desc.lower()
    ipList = {}
    for i in range(len(ingressList)):
        for k in ingressList[i]['IpRanges']:
            if bool(re.match(r"%s(.*)" % descLower, k['Description'])):
                ipList[k['CidrIp']] = k['Description']
    return ipList

def getSgDetails(client, id, desc):
    try:
        response = client.describe_security_groups(GroupIds=[id,],)
        for k,v in response.items():
            res = getExisitingIPList(v[0]['IpPermissions'],desc)
            return res
  
    except ClientError as e:
        return e

def addIptoSg(client, ipv4, id, desc, dt):
    description = desc + "-" + dt
    ip = ipv4+'/32'
    try:
        res = client.authorize_security_group_ingress(
            GroupId=id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'IpRanges':[
                        {
                            'CidrIp': ip,
                            'Description': description
                        },
                    ],
                },
            ],
        )
        if res['ResponseMetadata']['HTTPStatusCode'] == 200:
            cbGreen = "\x1b[1;40;42m"
            ctBlack = "\x1b[0m"
            return (cbGreen + "{} has been added to sg" + ctBlack).format(ip)
    except ClientError as e:
        return e

def dateGenrator():
    from datetime import datetime

    dt = datetime.now()
    dtFormat = str(dt.day) + "-" + str(dt.month) + "-" + str(dt.year)
    return dtFormat

def revokeIpfromSg(client, id, ipL):
    statusCod = {}
    for ip, desc in ipL.items():
        try:
            res = client.revoke_security_group_ingress(
                GroupId=id,
                IpPermissions=[
                    {
                        'IpProtocol': '-1',
                        'IpRanges': [
                            {
                                'CidrIp': ip,
                                'Description': desc
                            },
                        ],
                    },
                ],
            )
            statusCod[ip] = res['ResponseMetadata']['HTTPStatusCode']
        except ClientError as e:
            return e
    for ip,status in statusCod.items():
        if status == 200:
            cbRed = "\x1b[1;40;41m"
            ctBlack = "\x1b[0m"
            return (cbRed + "{} has been removed from sg" + ctBlack).format(ip)

def main():
    session = boto3.session.Session(profile_name=conf['profile'],region_name=conf['region'])
    client = session.client('ec2')

    if args.add:
        exstIP = getSgDetails(client, conf['sgId'], conf['description'])
        if len(exstIP) == 0:
            print("There is no previous IP in the description name {}".format(conf['description']))
            date = dateGenrator()
            curIP = getCurIpv4()
            resp = addIptoSg(client, curIP, conf['sgId'], conf['description'], date)
            print(resp)
        else:
            revokRes = revokeIpfromSg(client, conf['sgId'], exstIP)
            print(revokRes)
            date = dateGenrator()
            curIP = getCurIpv4()
            resp = addIptoSg(client, curIP, conf['sgId'], conf['description'], date)
            print(resp)

    if args.remove:
        exstIP = getSgDetails(client, conf['sgId'], conf['description'])
        revokRes = revokeIpfromSg(client, conf['sgId'], exstIP)
        print(revokRes)


if __name__ == "__main__":
    main()