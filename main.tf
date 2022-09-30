provider "aws" {
  region = local.region
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_id
}

data "aws_availability_zones" "available" {}

locals {
  name   = "nvflare"
  region = "us-west-2"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    GithubRepo = "github.com/bryantbiggs/nvflare-on-eks"
  }
}

################################################################################
# NVFlare Helm Release
################################################################################

resource "helm_release" "nvflare" {
  name             = "nvflare"
  description      = "A Helm chart for NVFlare overseer and servers"
  chart            = "${path.module}/chart"
  version          = "0.1.0"
  namespace        = "nvflare"
  create_namespace = true

  set {
    name  = "image.repository"
    value = var.image_repository
  }

  set {
    name  = "image.tag"
    value = var.image_tag
  }

  set {
    name  = "efsStorageClass.fileSystemId"
    value = aws_efs_file_system.this.id
  }
}

################################################################################
# EKS Cluster
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 18.30"

  cluster_name    = local.name
  cluster_version = "1.23"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    egress_all = {
      description = "Node all egress"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
    ingress_cluster_to_node_all_traffic = {
      description                   = "Cluster API to Nodegroup all traffic"
      protocol                      = "-1"
      from_port                     = 0
      to_port                       = 0
      type                          = "ingress"
      source_cluster_security_group = true
    }
  }

  eks_managed_node_groups = {
    nvflare = {
      instance_types = ["m5.large"]

      min_size     = 1
      max_size     = 10
      desired_size = 1
    }
  }

  tags = local.tags
}

################################################################################
# EC2 to "automate" NVFlare provisioning
################################################################################

resource "aws_iam_instance_profile" "this" {
  name = local.name
  role = aws_iam_role.this.name
}

resource "aws_iam_role" "this" {
  name_prefix = local.name

  assume_role_policy  = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Principal": {"Service": "ec2.amazonaws.com"},
          "Effect": "Allow",
          "Sid": ""
        }
      ]
    }
  EOF
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]

  tags = local.tags
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-2*-x86_64-gp2"]
  }
}

module "bastion_ec2" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  name = local.name

  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.medium"
  vpc_security_group_ids = [aws_security_group.bastion.id]
  subnet_id              = element(module.vpc.private_subnets, 0)
  iam_instance_profile   = aws_iam_instance_profile.this.name
  user_data_base64 = base64encode(
    <<-EOT
      #!/bin/bash

      MOUNT_DIR=~/efs_mount

      # Install pipenv
      amazon-linux-extras install epel -y \
      && yum install python-pip git -y

      cd ~

      # Setup EFS mount
      mkdir -p $MOUNT_DIR \
      && mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${element(local.azs, 0)}.${aws_efs_file_system.this.dns_name}:/ $MOUNT_DIR \
      && mkdir -p $${MOUNT_DIR}/workspace \
      && mkdir -p $${MOUNT_DIR}/persist \
      && chmod go+rw $MOUNT_DIR

      # NVflare
      python3 -m pip install setuptools -U \
      && python3 -m pip --quiet install -e "git+https://git@github.com/NVIDIA/NVFlare.git@dev#egg=nvflare-nightly" \
      && echo ${filebase64("${path.module}/project.yml")} | base64 --decode > ~/project.yml \
      && nvflare provision -p ~/project.yml \
      && mv ~/workspace/example_project/prod_00/* $${MOUNT_DIR}/workspace/
    EOT
  )

  tags = local.tags
}

resource "aws_security_group" "bastion" {
  name        = "${local.name}-bastion"
  description = "EC2 security group"
  vpc_id      = module.vpc.vpc_id

  egress {
    description = "Temp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
  }

  tags = local.tags
}

################################################################################
# EFS
################################################################################

resource "aws_efs_file_system" "this" {
  creation_token = local.name
  encrypted      = true

  tags = local.tags
}

resource "aws_efs_mount_target" "this" {
  count = length(module.vpc.private_subnets)

  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = module.vpc.private_subnets[count.index]
  security_groups = [aws_security_group.this.id]
}

resource "aws_security_group" "this" {
  name        = "${local.name}-efs"
  description = "EFS security group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "NFS access from private subnets"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
  }

  tags = local.tags
}

module "efs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.3"

  role_name             = "efs-csi"
  attach_efs_csi_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }

  tags = local.tags
}

resource "helm_release" "efs_csi" {
  name        = "aws-efs-csi-driver"
  description = "The AWS EFS CSI driver Helm chart deployment configuration"
  chart       = "aws-efs-csi-driver"
  repository  = "https://kubernetes-sigs.github.io/aws-efs-csi-driver/"
  version     = "2.2.7"
  namespace   = "kube-system"

  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.efs_csi_irsa.iam_role_arn
  }
}

################################################################################
# Supporting Resources
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Manage so we can name
  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.tags
}
