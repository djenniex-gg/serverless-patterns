#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { LambdaExtensionSecretsManagerCdkStack } from "../lib/lambda-extension-secrets-manager-cdk-stack";

const app = new cdk.App();
new LambdaExtensionSecretsManagerCdkStack(
  app,
  "LambdaExtensionSecretsManagerCdkStack",
);
