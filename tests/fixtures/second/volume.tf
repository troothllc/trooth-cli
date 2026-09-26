resource "aws_ebs_volume" "data" {
  size      = 8
  encrypted = true
}
