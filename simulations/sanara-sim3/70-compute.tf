resource "aws_iam_instance_profile" "app" {
  name = "sanara-mixed-app-profile"
  role = "sanara-mixed-app-role"
}
