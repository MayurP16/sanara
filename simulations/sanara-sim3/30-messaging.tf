resource "aws_sns_topic" "alerts" {
  name = "sanara-mixed-alerts"
  tags = local.tags
}

resource "aws_sqs_queue" "events" {
  name = "sanara-mixed-events"
  tags = local.tags
}
