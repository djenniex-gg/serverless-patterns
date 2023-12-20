import { Stack, StackProps, Duration, ArnFormat } from "aws-cdk-lib";
import { Construct } from "constructs";
import * as path from "path";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as iam from "aws-cdk-lib/aws-iam";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";

export class LambdaExtensionSecretsManagerCdkStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const secret = new Secret(this, "secret", {
      generateSecretString: {
        passwordLength: 30,
        excludeCharacters: '"@/',
      },
    });

    const checkLambda = new NodejsFunction(this, "CheckLambda", {
      runtime: lambda.Runtime.NODEJS_18_X,
      entry: path.join(__dirname, `/../lambda/index.ts`),
      handler: "handler",
      retryAttempts: 0,
      timeout: Duration.seconds(15),
      environment: {
        SECRET_ID: secret.secretName,
      },
      layers: [
        lambda.LayerVersion.fromLayerVersionArn(
          this,
          "SecretsManagerExtension",
          Stack.of(this).formatArn({
            account: "177933569100",
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
            resource: "layer",
            resourceName: "AWS-Parameters-and-Secrets-Lambda-Extension:11",
            service: "lambda",
          }),
        ),
      ],
    });

    // Set additional permissions for secrets manager
    checkLambda.role?.attachInlinePolicy(
      new iam.Policy(this, "additionalPermissionsForSecretsManager", {
        statements: [
          new iam.PolicyStatement({
            actions: ["secretsmanager:GetSecretValue"],
            resources: ["*"],
          }),
        ],
      }),
    );
  }
}
