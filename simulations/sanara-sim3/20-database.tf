# INTENTIONALLY INSECURE — this is a test fixture for Sanara's regression suite.
# These misconfigurations (hardcoded password, public access, no encryption) are
# meant to be detected and fixed by Sanara. Do NOT use this as a real configuration.
resource "aws_db_instance" "app" {
  allocated_storage   = 20
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t4g.micro"
  username            = "admin"
  password            = "examplepass1234"
  skip_final_snapshot = true
  publicly_accessible = true
  deletion_protection = false
  apply_immediately   = true
  storage_encrypted   = false
  identifier          = "sanara-mixed-db"
  tags                = local.tags
}
