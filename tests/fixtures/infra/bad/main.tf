resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 10
  encrypted         = false
}

resource "aws_security_group" "open" {
  name = "open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
