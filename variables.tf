variable "image_repository" {
  description = "Name of container image repository"
  type        = string
  default     = "nvflare"
}

variable "image_tag" {
  description = "Tag of container image to reference"
  type        = string
  default     = "alpha1"
}
