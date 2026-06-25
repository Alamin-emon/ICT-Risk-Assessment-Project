terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ─────────────────────────────
# CONNECT TO AWS
# ─────────────────────────────
provider "aws" {
  region = "eu-west-3"
}

# ─────────────────────────────
# AUTO FIND LATEST AMI
# ─────────────────────────────
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ─────────────────────────────
# MISCONFIGURATION 1: PUBLIC S3 BUCKET
# ─────────────────────────────
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "ict-risk-lab-public-bucket-2024"
  force_destroy = true

  tags = {
    Name    = "ict-risk-lab-public-bucket"
    Project = "ict-risk-lab"
    Risk    = "HIGH"
  }
}

resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_public" {
  bucket                  = aws_s3_bucket.vulnerable_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ─────────────────────────────
# MISCONFIGURATION 2: OVER-PERMISSIVE IAM USER
# ─────────────────────────────
resource "aws_iam_user" "vulnerable_user" {
  name = "ict-risk-lab-admin-user"

  tags = {
    Project = "ict-risk-lab"
    Risk    = "HIGH"
  }
}

resource "aws_iam_user_policy_attachment" "admin_access" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ─────────────────────────────
# VPC - PRIVATE NETWORK
# ─────────────────────────────
resource "aws_vpc" "lab_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name    = "ict-risk-lab-vpc"
    Project = "ict-risk-lab"
  }
}

# ─────────────────────────────
# SUBNET - SECTION OF THE NETWORK
# ─────────────────────────────
resource "aws_subnet" "lab_subnet" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name    = "ict-risk-lab-subnet"
    Project = "ict-risk-lab"
  }
}

# ─────────────────────────────
# INTERNET GATEWAY - CONNECTS VPC TO INTERNET
# ─────────────────────────────
resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.lab_vpc.id

  tags = {
    Name    = "ict-risk-lab-igw"
    Project = "ict-risk-lab"
  }
}

# ─────────────────────────────
# ROUTE TABLE - TRAFFIC RULES
# ─────────────────────────────
resource "aws_route_table" "lab_rt" {
  vpc_id = aws_vpc.lab_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab_igw.id
  }

  tags = {
    Name    = "ict-risk-lab-rt"
    Project = "ict-risk-lab"
  }
}

resource "aws_route_table_association" "lab_rta" {
  subnet_id      = aws_subnet.lab_subnet.id
  route_table_id = aws_route_table.lab_rt.id
}

# ─────────────────────────────
# MISCONFIGURATION 3: OPEN SECURITY GROUP
# ─────────────────────────────
resource "aws_security_group" "vulnerable_sg" {
  name   = "ict-risk-lab-open-sg"
  vpc_id = aws_vpc.lab_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH open to world - INTENTIONAL LAB"
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP open to world - INTENTIONAL LAB"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "ict-risk-lab-open-sg"
    Project = "ict-risk-lab"
    Risk    = "HIGH"
  }
}

# ─────────────────────────────
# MISCONFIGURATION 4: EC2 INSTANCE
# ─────────────────────────────
resource "aws_instance" "vulnerable_ec2" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  subnet_id                   = aws_subnet.lab_subnet.id
  vpc_security_group_ids      = [aws_security_group.vulnerable_sg.id]
  associate_public_ip_address = true

  # IMDSv2 not enforced - intentional misconfiguration
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  # No encryption - intentional misconfiguration
  root_block_device {
    volume_size = 8
    encrypted   = false
  }

  tags = {
    Name    = "ict-risk-lab-ec2"
    Project = "ict-risk-lab"
    Risk    = "HIGH"
  }
}