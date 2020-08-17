variable "function_name" {
  description = "A unique name for your Lambda function (and related IAM resources)"
  type        = "string"
}

variable "handler" {
  description = "The function entrypoint in your code"
  type        = "string"
}

variable "build_script" {
  description = "The path to the script which will compile a zip of the lambda function"
  type        = "string"
  default     = ""
}

variable "memory_size" {
  description = "Amount of memory in MB your Lambda function can use at runtime"
  type        = "string"
  default     = 128
}

variable "reserved_concurrent_executions" {
  description = "The amount of reserved concurrent executions for this Lambda function"
  type        = "string"
  default     = -1
}

variable "runtime" {
  description = "The runtime environment for the Lambda function"
  type        = "string"
}

variable "layers" {
  description = "List of Lambda Layer Version ARNs to attach to your Lambda Function."
  type        = "list"
  default     = []
}

variable "timeout" {
  description = "The amount of time your Lambda function had to run in seconds"
  type        = "string"
  default     = 10
}

variable "source_path" {
  description = "The source file or directory containing your Lambda source code"
  type        = "string"
}

variable "description" {
  description = "Description of what your Lambda function does"
  type        = "string"
  default     = "Managed by Terraform"
}

variable "environment" {
  description = "Environment configuration for the Lambda function"
  type        = "map"
  default     = {}
}

variable "dead_letter_config" {
  description = "Dead letter configuration for the Lambda function"
  type        = "map"
  default     = {}
}

variable "attach_dead_letter_config" {
  description = "Set this to true if using the dead_letter_config variable"
  type        = "string"
  default     = false
}

variable "vpc_config" {
  description = "VPC configuration for the Lambda function"
  type        = "map"
  default     = {}
}

variable "attach_vpc_config" {
  description = "Set this to true if using the vpc_config variable"
  type        = "string"
  default     = false
}

variable "tags" {
  description = "A mapping of tags"
  type        = "map"
  default     = {}
}

variable "policy" {
  description = "An addional policy to attach to the Lambda function"
  type        = "string"
  default     = ""
}

variable "attach_policy" {
  description = "Set this to true if using the policy variable"
  type        = "string"
  default     = false
}

variable "enable_cloudwatch_logs" {
  description = "Set this to false to disable logging your Lambda output to CloudWatch Logs"
  type        = "string"
  default     = true
}
