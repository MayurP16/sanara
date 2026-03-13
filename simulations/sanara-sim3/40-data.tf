resource "aws_dynamodb_table" "events" {
  name         = "sanara-mixed-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = local.tags
}
