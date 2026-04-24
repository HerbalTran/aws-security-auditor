#Đây là file python hoàn thiện. Có bổ sung thêm phần kiểm tra tồn tại file 
#Và xử lý cả rule IPv6 để phát hiện lỗ hổng mở port cho toàn bộ Internet (cả IPv4 và IPv6)

import boto3
import csv
import os  # Thư viện mới được thêm vào để xử lý đường dẫn file
from datetime import datetime

# Lấy ngày tháng hiện tại
today = datetime.now().strftime('%Y-%m-%d')
header_data = ['SG_ID', 'SG_name', 'VpcId', 'Port_open','Alert', 'Date']
file_path = 'sg_report1.csv'

# 1. Kiểm tra xem file đã tồn tại hay chưa
file_exists = os.path.exists(file_path)

# Xác định chế độ mở file: 'a' (append) nếu file đã có, 'w' (write) nếu chưa có
file_mode = 'a' if file_exists else 'w'

# Khởi tạo client kết nối đến dịch vụ EC2
ec2_client = boto3.client(
    'ec2', 
    region_name='us-east-1',
    endpoint_url='http://localhost:4566' # Đang trỏ về LocalStack
)

# Mở file với chế độ tự động thay đổi (file_mode)
with open(file_path, mode=file_mode, newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    
    # 2. Xử lý Header: Chỉ ghi tiêu đề cột nếu file chưa từng tồn tại
    if not file_exists:
        writer.writerow(header_data)
    
    # Gọi API lấy danh sách SG
    response = ec2_client.describe_security_groups()
    sgs = response['SecurityGroups']

    for sg in sgs:
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        vpc_id = sg.get('VpcId', 'N/A')
        
        # Dùng .get() thay vì [] để tránh lỗi khi SG không có IpPermissions
        for rule in sg.get('IpPermissions', []):
            port = rule.get('FromPort')
            
            if port in [22, 3389]:
                # 3a. Quét qua các dải IPv4
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        warning_msg = f"Critical: Port {port} is OPEN to IPv4 Internet!"
                        writer.writerow([sg_id, sg_name, vpc_id, port, warning_msg, today])
                        print(f"Phát hiện lỗ hổng: {sg_name} ({sg_id}) đang mở port {port} cho IPv4!")

                # 3b. Quét qua các dải IPv6 (Khối code bổ sung)
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    if ipv6_range.get('CidrIpv6') == '::/0':
                        warning_msg = f"Critical: Port {port} is OPEN to IPv6 Internet!"
                        writer.writerow([sg_id, sg_name, vpc_id, port, warning_msg, today])
                        print(f"Phát hiện lỗ hổng: {sg_name} ({sg_id}) đang mở port {port} cho IPv6!")