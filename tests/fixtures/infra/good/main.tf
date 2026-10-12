resource "aws_s3_bucket" "private" {
  bucket = "my-private-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private" {
  bucket = aws_s3_bucket.private.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "private" {
  bucket        = aws_s3_bucket.private.id
  target_bucket = aws_s3_bucket.private.id
  target_prefix = "log/"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 10
  encrypted         = true
}

resource "aws_security_group" "restricted" {
  name = "restricted"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
