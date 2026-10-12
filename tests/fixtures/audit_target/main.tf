# Intentionally insecure fixture: public bucket, unencrypted volume and a
# security group open to the whole internet.

terraform {
  required_version = ">= 1.5"
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "public_assets" {
  bucket = "audit-target-public"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name = "audit-target-open"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 10
  encrypted         = false
}
