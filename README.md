# NVIDIA NVFlare on EKS

This example shows how to deploy [NVFlare (NVIDIA Federated Learning Application Runtime Environment)](https://github.com/NVIDIA/NVFlare) on EKS.

## Prerequisites:

Ensure that you have the following tools installed locally:

1. [aws cli](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
2. [kubectl](https://Kubernetes.io/docs/tasks/tools/)
3. [terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli)
4. [docker](https://docs.docker.com/get-docker/)

## Deploy

NVFlare is still under active development. Please check the [project](https://github.com/NVIDIA/NVFlare) for updates and open any questions/issues related to the framework there as well.

1. Setup variables used in following commands to sync between manual commands and Terraform variables. The region, image repository name, and tag can all be adjusted here to suit:

```sh
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
export AWS_REGION=us-west-2
export REPOSITORY_NAME=nvflare
export TF_VAR_image_repository=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPOSITORY_NAME}
export TF_VAR_image_tag=alpha1
```

2. Retrieve an authentication token and authenticate your Docker client to your registry. Use the AWS CLI:

```sh
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
```

3. Create an ECR repository to store the container image that will be used to deploy NVFlare:

```sh
aws ecr create-repository --repository-name $REPOSITORY_NAME --region $AWS_REGION
```

4. Build, tag and push the image to the ECR repository created:

```sh
docker build -t ${TF_VAR_image_repository}:${TF_VAR_image_tag} .
docker push ${TF_VAR_image_repository}:${TF_VAR_image_tag}
```

5. Provision the example:

```sh
terraform init
terraform apply
```

Enter `yes` at command prompt to apply

## Validate

The following command will update the `kubeconfig` on your local machine and allow you to interact with your EKS Cluster using `kubectl` to validate the CoreDNS deployment for Fargate.

1. Run `update-kubeconfig` command:

```sh
aws eks --region <REGION> update-kubeconfig --name nvflare
```

2. Test by listing all the pods running currently. The CoreDNS pod should reach a status of `Running` after approximately 60 seconds:

```sh
kubectl get pods -n nvflare

# Output should look like below
TODO
```

3. Test by executing a training job

```sh
TODO
```

## Destroy

To teardown and remove the resources created in this example:

```sh
terraform destroy
```
