###############################################################
# INTENTIONALLY VULNERABLE Terraform - for testing only
# Production-tagged resources with CIS violations everywhere
###############################################################

provider "aws" {
  region = "us-east-1"
}

# --- S3: public + unencrypted + no versioning ---
resource "aws_s3_bucket" "prod_data" {
  bucket = "my-production-customer-data"
  acl    = "public-read"

  versioning {
    enabled = false
  }
  tags = {
    Environment = "production"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-prod-logs-bucket"
  acl    = "public-read-write"
}

# --- Security groups: wide open to the internet ---
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "production web sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- RDS: publicly accessible + unencrypted ---
resource "aws_db_instance" "prod_db" {
  identifier             = "production-postgres"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  publicly_accessible    = true
  storage_encrypted      = false
  skip_final_snapshot    = true
}

# --- EBS volume unencrypted ---
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# --- CloudTrail not multi-region, logging off ---
resource "aws_cloudtrail" "main" {
  name                          = "main"
  s3_bucket_name                = "cloudtrail-bucket"
  is_multi_region_trail         = false
  enable_logging                = false
}

# --- KMS without rotation ---
resource "aws_kms_key" "main" {
  description         = "main key"
  enable_key_rotation = false
}

# --- IAM user with AdministratorAccess ---
resource "aws_iam_user" "dev" {
  name = "dev-user"
}

resource "aws_iam_user_policy_attachment" "dev_admin" {
  user       = aws_iam_user.dev.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --- VPC without flow logs ---
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  enable_flow_log  = false
}
