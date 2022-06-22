#1 Create a VPC
resource "aws_vpc" "UST1Pap_Vpc" {
  cidr_block       = var.UST1_Pap_vpc_cidr
  instance_tenancy = "default"

  tags = {
    Name = "UST1Pap_Vpc"
  }
}

#2 Create Public Subnet 01
resource "aws_subnet" "UST1Pap_PubSN1" {
  vpc_id            = aws_vpc.UST1Pap_Vpc.id
  cidr_block        = var.UST1Pap_PubSN1_cidr
  availability_zone = var.availability_zone1

  tags = {
    Name = "UST1Pap_PubSN1"
  }
}

#3 Create Public Subnet 02
resource "aws_subnet" "UST1Pap_PubSN2" {
  vpc_id            = aws_vpc.UST1Pap_Vpc.id
  cidr_block        = var.UST1Pap_PubSN2_cidr
  availability_zone = var.availability_zone2

  tags = {
    Name = "UST1Pap_PubSN2"
  }
}


#4 Create Private Subnet 01
resource "aws_subnet" "UST1Pap_PrvSN1" {
  vpc_id            = aws_vpc.UST1Pap_Vpc.id
  cidr_block        = var.UST1Pap_PrvSN1_cidr
  availability_zone = var.availability_zone1
  tags = {
    Name = "UST1Pap_PrvSN1"
  }
}

#5 Create Private Subnet 02
resource "aws_subnet" "UST1Pap_PrvSN2" {
  vpc_id            = aws_vpc.UST1Pap_Vpc.id
  cidr_block        = var.UST1Pap_PrvSN2_cidr
  availability_zone = var.availability_zone2
  tags = {
    Name = "UST1Pap_PrvSN2"
  }
}

#6 Create Internet Gateway
resource "aws_internet_gateway" "UST1Pap_IGW" {
  vpc_id = aws_vpc.UST1Pap_Vpc.id

  tags = {
    Name = "UST1Pap_IGW"
  }
}

#7 Create Public Route Table
resource "aws_route_table" "UST1Pap_PubRT" {
  vpc_id = aws_vpc.UST1Pap_Vpc.id

  route {
    cidr_block = var.all_cidr
    gateway_id = aws_internet_gateway.UST1Pap_IGW.id
  }

  tags = {
    Name = "UST1Pap_PubRT"
  }
}

#8 Create Route Table Association for Public Subnet 01
resource "aws_route_table_association" "UST1Pap_RTAssoc1" {
  subnet_id      = aws_subnet.UST1Pap_PubSN1.id
  route_table_id = aws_route_table.UST1Pap_PubRT.id
}

#9 Create Route Table Association for Public Subnet 02
resource "aws_route_table_association" "UST1Pap_RTAssoc2" {
  subnet_id      = aws_subnet.UST1Pap_PubSN2.id
  route_table_id = aws_route_table.UST1Pap_PubRT.id
}

#10 Create NAT Gateway
resource "aws_nat_gateway" "UST1_NAT" {
  allocation_id = aws_eip.UST1_EIP.id
  subnet_id     = aws_subnet.UST1Pap_PubSN1.id

  tags = {
    Name = "UST1_NAT"
  }
}

#11 Create Elastic IP Address for NAT Gateway
resource "aws_eip" "UST1_EIP" {
  vpc = true
}

#12 Create Private_Route Table
resource "aws_route_table" "UST1Pap_PrvSNRT" {
  vpc_id = aws_vpc.UST1Pap_Vpc.id

  route {
    cidr_block     = var.all_cidr
    nat_gateway_id = aws_nat_gateway.UST1_NAT.id
  }

  tags = {
    Name = "UST1Pap_PrvSNRT"
  }
}

#13 Create Private Subnet 01 Association
resource "aws_route_table_association" "UST1Pap_PrvSN1RTAss" {
  subnet_id      = aws_subnet.UST1Pap_PrvSN1.id
  route_table_id = aws_route_table.UST1Pap_PrvSNRT.id
}

#14 Create Private Subnet 02 Association
resource "aws_route_table_association" "UST1Pap_PrvSN2RTAss" {
  subnet_id      = aws_subnet.UST1Pap_PrvSN2.id
  route_table_id = aws_route_table.UST1Pap_PrvSNRT.id
}

#15 Create Jenkins Security Group
resource "aws_security_group" "UST1Pap_JenkinsSG" {
  name        = "UST1Pap_JenkinsSG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.UST1Pap_Vpc.id

  ingress {
    description = "ssh from VPC"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all_cidr]
  }

  ingress {
    description = "jenkins port from VPC"
    from_port   = var.port_jenkins
    to_port     = var.port_jenkins
    protocol    = "tcp"
    cidr_blocks = [var.all_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = [var.all_cidr]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "UST1Pap_JenkinsSG"
  }
}

#16 Declare Key Pair
resource "aws_key_pair" "USTeam1KeyPair" {
  key_name   = "USTeam1KeyPair"
  public_key = file(var.path_to_public_key)
}

#17 Create Jenkins Server  (using Red Hat for ami and t2.medium for instance type)
resource "aws_instance" "UST1_Jenkins_Server" {
  ami                         = var.ami
  instance_type               = var.instance_type_medium
  vpc_security_group_ids      = ["${aws_security_group.UST1Pap_JenkinsSG.id}"]
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.UST1Pap_PubSN1.id
  availability_zone           = var.availability_zone1
  key_name                    = aws_key_pair.USTeam1KeyPair.key_name

  user_data = <<-EOF
  #!bin/bash
  sudo yum update -y
  sudo yum install wget -y
  sudo yum install git -y
  sudo yum install maven -y
  sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
  sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key
  sudo yum update -y
  sudo yum upgrade -y
  sudo yum install jenkins java-1.8.0-openjdk-devel -y --nobest
  sudo systemctl start jenkins
  sudo systemctl enable jenkins
  echo "license_key: 984fd9395376105d6273106ec42913a399a2NRAL" | sudo tee -a /etc/newrelic-infra.yml
  sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
  sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
  sudo yum install newrelic-infra -y
  sudo yum install sshpass -y
  sudo su
  echo Admin123@ | passwd ec2-user --stdin
  echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
  sudo sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sudo service sshd reload
  su - ec2-user -c "ssh-keygen -f ~/.ssh/UST1papjenkey_rsa -t rsa -b 4096 -m PEM -N ''"
  sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
  sudo su - ec2-user -c 'sshpass -p "Admin123@" ssh-copy-id -i /home/ec2-user/.ssh/UST1papjenkey_rsa.pub ec2-user@${data.aws_instance.UST1Pap_Ansible_IP.public_ip} -p 22'
  EOF

  tags = {
    Name = "UST1_Jenkins_Server"
  }
}

#18 Create Data Resource for for Ansible-IP
data "aws_instance" "UST1Pap_Ansible_IP" {
  filter {
    name   = "tag:Name"
    values = ["UST1pap_Ansible"]
  }
  depends_on = [
    aws_instance.UST1pap_Ansible_host,
  ]
}

#19 Create FrontEnd Security Group for Docker
resource "aws_security_group" "UST1Pap_DockerSG" {
  name        = "UST1Pap_DockerSG"
  description = "Allow inbound Traffic"
  vpc_id      = aws_vpc.UST1Pap_Vpc.id
  ingress {
    description = "Allow SSH access"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all_cidr]
  }

  ingress {
    description = "Allow HTTP access"
    from_port   = var.port_http
    to_port     = var.port_http
    protocol    = "tcp"
    cidr_blocks = [var.all_cidr]
  }

  ingress {
    description = "Proxy from VPC"
    from_port   = var.port_docker
    to_port     = var.port_docker
    protocol    = "tcp"
    cidr_blocks = [var.all_cidr]
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = [var.all_cidr]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "UST1Pap_DockerSG"
  }
}

#20 Create EC2 Instance for Docker host using a t2.micro RedHat ami
resource "aws_instance" "UST1pap_Docker_host" {
  ami                         = var.ami
  instance_type               = var.instance_type_t2micro
  subnet_id                   = aws_subnet.UST1Pap_PubSN1.id
  vpc_security_group_ids      = ["${aws_security_group.UST1Pap_DockerSG.id}"]
  associate_public_ip_address = true
  availability_zone           = var.availability_zone1
  key_name                    = aws_key_pair.USTeam1KeyPair.key_name

  user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker 
sudo systemctl enable docker
echo Admin123@ | passwd ec2-user --stdin
echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo service sshd reload
su - ec2-user
# sudo chmod -R 700 .ssh/
# sudo chmod 600 .ssh/authorized_keys
echo "license_key: 2321a849d57e69fe9b28378de6b0c5ebb3ceNRAL" | sudo tee -a /etc/newrelic-infra.yml 
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo usermod -aG docker ec2-user
docker run hello-world
EOF

  tags = {
    Name = "UST1pap_Docker_host"
  }
}

#21 Create Data Resource for for Docker-IP
data "aws_instance" "UST1Pap_Docker_IP" {
  filter {
    name   = "tag:Name"
    values = ["UST1pap_Docker_host"]
  }
  depends_on = [
    aws_instance.UST1pap_Docker_host,
  ]
}

#22 Create Ansible Security Group
resource "aws_security_group" "UST1Pap_AnsibleSG" {
  name        = "UST1Pap_AnsibleSG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.UST1Pap_Vpc.id

  ingress {
    description = "ssh from VPC"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = [var.all_cidr]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "UST1Pap_AnsibleSG"
  }
}

#23 Create Ansible Instance Host
resource "aws_instance" "UST1pap_Ansible_host" {
  ami                         = var.ami
  instance_type               = var.instance_type_t2micro
  subnet_id                   = aws_subnet.UST1Pap_PubSN1.id
  vpc_security_group_ids      = ["${aws_security_group.UST1Pap_AnsibleSG.id}"]
  associate_public_ip_address = true
  availability_zone           = var.availability_zone1
  key_name                    = aws_key_pair.USTeam1KeyPair.key_name
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install python3.8 -y
sudo alternatives --set python /usr/bin/python3.8
sudo yum -y install python3-pip
sudo yum install ansible -y
pip3 install ansible --user
sudo yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/sshpass-1.06-2.el7.x86_64.rpm
sudo yum install sshpass -y
sudo su
echo Admin123@ | passwd ec2-user --stdin
echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo service sshd reload
su - ec2-user
# sudo chown -R ec2-user:ec2-user/.ssh/authorized_keys
# sudo chmod 600 /home/ec2-user/.ssh/authorized_keys
# sudo chown ec2-user:ec2-user/etc/ansible
su - ec2-user -c "ssh-keygen -f ~/.ssh/UST1papanskey_rsa -t rsa -N ''"
sudo bash -c ' echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
sudo su - ec2-user -c 'sshpass -p "Admin123@" ssh-copy-id -i /home/ec2-user/.ssh/UST1papanskey_rsa.pub ec2-user@${data.aws_instance.UST1Pap_Docker_IP.public_ip} -p 22'
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user
cd /etc
sudo chown ec2-user:ec2-user hosts
cat <<EOT>> /etc/ansible/hosts
localhost ansible_connection=local
[docker_host]
${data.aws_instance.UST1Pap_Docker_IP.public_ip}  ansible_ssh_private_key_file=/home/ec2-user/.ssh/UST1papanskey_rsa
EOT
sudo chown -R ec2-user:ec2-user /opt/
sudo chown -R ec2-user:ec2-user docker/
sudo mkdir /opt/docker
sudo chmod 700 home/ec2-user/opt/docker
touch /opt/docker/Dockerfile
cat <<EOT>> /opt/docker/Dockerfile
# pull tomcat image from docker hub
FROM tomcat
FROM openjdk
LABEL MAINTAINER UST1
#copy war file on the container
COPY ./spring-petclinic-2.4.2.war app/
WORKDIR app/
ENTRYPOINT [ "java", "-jar", "spring-petclinic-2.4.2.war", "--server.port=8085" ]
EOT
touch /opt/docker/docker-image.yml
cat <<EOT>> /opt/docker/docker-image.yml
---
 - hosts: all
  #root access to user
   become: true
   tasks:
   - name: login to dockerhub
     command: docker login -u cloudhight -p CloudHight_Admin123@
   - name: Create docker image from Pet Adoption war file
     command: docker build -t pet-adoption-image .
     args:
       chdir: /opt/docker
   - name: Add tag to image
     command: docker tag pet-adoption-image cloudhight/pet-adoption-image
   - name: Push image to docker hub
     command: docker push cloudhight/pet-adoption-image
   - name: Remove docker image from Ansible node
     command: docker rmi pet-adoption-image cloudhight/pet-adoption-image
     ignore_errors: yes
EOT
touch /opt/docker/docker-container.yml
cat <<EOT>> /opt/docker/docker-container.yml
---
 - hosts: all
   become: true
   tasks:
   - name: login to dockerhub
     command: docker login -u cloudhight -p CloudHight_Admin123@
   - name: Stop any container running
     command: docker stop pet-adoption-container
     ignore_errors: yes
   - name: Remove stopped container
     command: docker rm pet-adoption-container
     ignore_errors: yes
   - name: Remove docker image
     command: docker rmi cloudhight/pet-adoption-image
     ignore_errors: yes
   - name: Pull docker image from dockerhub
     command: docker pull cloudhight/pet-adoption-image
     ignore_errors: yes
   - name: Create container from pet adoption image
     command: docker run -it -d --name pet-adoption-container -p 8080:8085 cloudhight/pet-adoption-image
     ignore_errors: yes
EOT
touch /opt/docker/newrelic.yml
cat <<EOT>> /opt/docker/newrelic.yml
---
 - hosts: all
   become: true
   tasks:
   - name: install newrelic agent
     command: docker run \
                     -d \
                     --name newrelic-infra \
                     --network=host \
                     --cap-add=SYS_PTRACE \
                     --privileged \
                     --pid=host \
                     -v "/:/host:ro" \
                     -v "/var/run/docker.sock:/var/run/docker.sock" \
                     -e NRIA_LICENSE_KEY=984fd9395376105d6273106ec42913a399a2NRAL \ 
                     newrelic/infrastructure:latest
EOT
EOF 
  tags = {
    Name = "UST1pap_Ansible"
  }
}

#24 Create BackEnd Security Group
resource "aws_security_group" "UST1Pap_BackEndSG" {
  name        = "UST1Pap_BackEndSG"
  description = "Allow inbound Traffic"
  vpc_id      = aws_vpc.UST1Pap_Vpc.id
  ingress {
    description = "Allow SSH access"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.UST1Pap_PubSN1_cidr]
  }
  ingress {
    description = "Allow Mysql access"
    from_port   = var.port_mysql
    to_port     = var.port_mysql
    protocol    = "tcp"
    cidr_blocks = [var.UST1Pap_PubSN1_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.all_cidr]
  }
  tags = {
    Name = "UST1Pap_BackEndSG"
  }
}

#25 Create Database Subnet Group - (name must be lowercase)
resource "aws_db_subnet_group" "ust1-sng" {
  name       = "ust1"
  subnet_ids = ["${aws_subnet.UST1Pap_PrvSN1.id}", "${aws_subnet.UST1Pap_PrvSN2.id}"]
}

#26 Create MySQL Database
resource "aws_db_instance" "US_Team1_DB" {
  allocated_storage      = var.storage_size
  engine                 = var.db_engine
  engine_version         = var.db_engine_version
  instance_class         = var.db_instance_class
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  vpc_security_group_ids = [aws_security_group.UST1Pap_BackEndSG.id]
  parameter_group_name   = var.db_parameter_group_name
  port                   = var.port_mysql
  skip_final_snapshot    = true
  multi_az               = false
  db_subnet_group_name   = aws_db_subnet_group.ust1-sng.name
}

#27 Create a target group for LB
resource "aws_lb_target_group" "UST1pap-TG-LB" {
  name        = "UST1pap-TG-LB"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.UST1Pap_Vpc.id
  target_type = "instance"
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 60
    interval            = 90
  }
}

#28 Create a target group attachment
resource "aws_lb_target_group_attachment" "UST1pap-TG-attachment" {
  target_group_arn = aws_lb_target_group.UST1pap-TG-LB.arn
  target_id        = aws_instance.UST1pap_Docker_host.id
  port             = 8080
}

#29 Create application load balancer
resource "aws_lb" "UST1pap-lb" {
  name               = "UST1pap-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.UST1Pap_DockerSG.id]
  subnets            = [aws_subnet.UST1Pap_PubSN1.id, aws_subnet.UST1Pap_PubSN2.id]

  enable_deletion_protection = false
  tags = {
    Environment = "production"
  }
}

#30 Add load balancer listener
resource "aws_lb_listener" "UST1pap-lb-listener" {
  load_balancer_arn = aws_lb.UST1pap-lb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.UST1pap-TG-LB.arn
  }
}

#31 create ami for docker host
resource "aws_ami_from_instance" "UST1pap-AMI" {
  name                    = "UST1pap-AMI"
  source_instance_id      = aws_instance.UST1pap_Docker_host.id
  snapshot_without_reboot = true

  depends_on = [
    aws_instance.UST1pap_Docker_host
  ]
}

#32 Launch configuration for autoscaling group (ASG)
resource "aws_launch_configuration" "UST1pap-lc" {
  name                        = "UST1pap-lc"
  image_id                    = aws_ami_from_instance.UST1pap-AMI.id
  instance_type               = var.instance_type_t2micro
  associate_public_ip_address = true
  key_name                    = aws_key_pair.USTeam1KeyPair.key_name
  security_groups             = ["${aws_security_group.UST1Pap_DockerSG.id}"]
}

#33 Create ASG Autoscaling group
resource "aws_autoscaling_group" "UST1pap-asg" {
  name                      = "UST1pap-asg"
  max_size                  = 2
  min_size                  = 2
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2
  force_delete              = true
  launch_configuration      = aws_launch_configuration.UST1pap-lc.name
  vpc_zone_identifier       = [aws_subnet.UST1Pap_PubSN1.id, aws_subnet.UST1Pap_PubSN1.id]
  target_group_arns         = [aws_lb_target_group.UST1pap-TG-LB.arn]

  tag {
    key                 = "Name"
    value               = "UST1pap-asg"
    propagate_at_launch = true
  }
}

#34 Create Autoscaling Policy
resource "aws_autoscaling_policy" "UST1pap-asg-policy" {
  name                   = "UST1pap-asg-policy"
  policy_type            = "TargetTrackingScaling"
  autoscaling_group_name = aws_autoscaling_group.UST1pap-asg.name # or "lawal-asg"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60
  }
}

#35 Provision aws route_53 
resource "aws_route53_zone" "UST1pap-zone" {
  name = "consultlawal.com"
}

#36 Create Route 53 A Record and Alias
resource "aws_route53_record" "UST1pap-record" {
  zone_id = aws_route53_zone.UST1pap-zone.zone_id
  name    = "consultlawal"
  type    = "A"

  alias {
    name                   = aws_lb.UST1pap-lb.dns_name
    zone_id                = aws_lb.UST1pap-lb.zone_id
    evaluate_target_health = true
  }
}
