from influxdb import InfluxDBClient
client = InfluxDBClient(
    host='192.168.99.100',
    port=8086,
    username='root',
    password='root',
    database='networkStats')
print "----------------------------------------"
print "TEMPORARY API TO CHANGE HOST INFORMATION"
print "----------------------------------------"
print "DEFAULT VALUES ARE;"
print "measurement: 'UserInfo'"
print "host: ''"
print "permission:'N/A', limit: 10000, facebook: 'Allow', youtube:'Allow', ports: 'n/a'"
print "----------------------------------------"
print "USAGE:\nType the host you want to alter\nType the parameters you want to change and leave the others empty and press enter!"
print "----------------------------------------"
json_user = [{"measurement": "UserInfo",
              "tags": {"host": ''},
              "fields": {"permission": "N/A",
                         "limit": 10000,
                         "facebook": 'Allow',
                         "youtube": 'Allow',
                         "ports": 'n/a'}}]

json_body = [{"measurement": "BandwidthUsage",
              "tags": {}, "fields": {}}]
host = raw_input("Enter the host: ")
ports = raw_input("Enter the host ports: ")
permission = raw_input("Enter the host permission: ")
limit = raw_input("Enter the host limit: ")
facebook = raw_input("Enter the host Facebook permission: ")
youtube = raw_input("Enter the host Youtube permission: ")
print host
json_user[0]["tags"]["host"] = host
if ports != '':
    json_user[0]["fields"]["ports"] = ports
if permission != '':
    json_user[0]["fields"]["permission"] = permission
if limit != '':
    json_user[0]["fields"]["limit"] = int(limit)
if facebook != '':
    json_user[0]["fields"]["facebook"] = facebook
if youtube != '':
    json_user[0]["fields"]["youtube"] = youtube
client.write_points(json_user)

'''
parameters = {}
rs = client.query(
    "select last(*) from UserInfo where host='%s';" %
    host)

for item in list(rs.get_points(measurement='UserInfo'))[0].keys():
    if item == 'last_ports':
        if list(rs.get_points(measurement='UserInfo'))[0][item] != None:
            ports = list(rs.get_points(measurement='UserInfo'))[
                0][item].split(",")
        else:
            ports = ''
        parameters[item] = ports
        print ports
    else:
        parameters[item] = list(rs.get_points(measurement='UserInfo'))[0][item]
'''
