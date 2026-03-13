resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/sanara-mixed/app"
  retention_in_days = 14
  tags              = local.tags
}
