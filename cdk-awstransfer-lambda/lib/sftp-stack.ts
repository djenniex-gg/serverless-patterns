import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CfnServer, CfnUser } from 'aws-cdk-lib/aws-transfer';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from "aws-cdk-lib/aws-logs";
import * as agw from "aws-cdk-lib/aws-apigateway";
import * as path from "path";
import { NodejsFunction, SourceMapMode } from "aws-cdk-lib/aws-lambda-nodejs";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sm from "aws-cdk-lib/aws-secretsmanager";

const AWSParametersAndSecretsLambdaExtension: {
  [region: string]: { AccountId: string };
} = {
  "us-east-1": { AccountId: "177933569100"},
  "us-west-2": { AccountId: "590474943231"},
};

export class sftpStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const apiLog = new logs.LogGroup(this, 'apiLog', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    } as any);

    const api = new agw.RestApi(this, "authApi", {
      description: "Transfer Service Auth API",
      deployOptions: {
        accessLogDestination: new agw.LogGroupLogDestination(apiLog),
        accessLogFormat: agw.AccessLogFormat.jsonWithStandardFields(),
      },
    });

    const paramsAndSecrets = lambda.ParamsAndSecretsLayerVersion.fromVersion(
      lambda.ParamsAndSecretsVersions.V1_0_103
    );

    const authHandler = new NodejsFunction(this, "AuthHandler", {
      bundling: {
        externalModules: [
          "aws-sdk",
        ],
        nodeModules: [
          "ipaddr.js",
        ],
        minify: false,
        sourcesContent: true,
        sourceMap: true, // include source map, defaults to false
        sourceMapMode: SourceMapMode.INLINE, // defaults to SourceMapMode.DEFAULT
      },
      depsLockFilePath: path.join(__dirname, "../lambda/package-lock.json"),
      description: "Custom authorizer for Transfer Service",
      entry: path.join(__dirname, "../lambda/index.ts"),
      paramsAndSecrets,
      logRetention: logs.RetentionDays.ONE_WEEK,
      memorySize: 128,
      projectRoot: path.join(__dirname, "../lambda/"),
      runtime: lambda.Runtime.NODEJS_18_X,
      timeout: cdk.Duration.minutes(2),
    });

    const route = api.root
      .addResource("servers")
      .addResource("{serverId}")
      .addResource("users")
      .addResource("{username}")
      .addResource("config");
    route.addMethod("GET", new agw.LambdaIntegration(authHandler), {
      authorizationType: agw.AuthorizationType.IAM,
    });

    const loggingRole = new iam.Role(this, 'loggingRole', {
      assumedBy: new iam.ServicePrincipal('transfer.amazonaws.com'),
      description: 'logging role for SFTP server'
    });

    loggingRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSTransferLoggingAccess"));

    const authenticationRole = new iam.Role(this, "AuthenticationRole", {
      assumedBy: new iam.ServicePrincipal("transfer.amazonaws.com"),
      description: "Authentication role for Transfer Server",
    });
    authenticationRole.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        resources: [api.arnForExecuteApi()],
        actions: ["execute-api:Invoke"],
      }),
    );

   const server = new CfnServer(this, 'server', {
     domain: 'S3',
     endpointType: 'PUBLIC',
     identityProviderType: "API_GATEWAY",
     loggingRole: loggingRole.roleArn,
     identityProviderDetails: {
      url: api.url,
      invocationRole: authenticationRole.roleArn,
    },
     protocols: ['SFTP'],
   });

   const serverId = server.attrServerId;

    // cannot use inline policy due to circular dependency
    const authHandlerPolicy = new iam.Policy(this, "AuthHandlerPolicy", {
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: [
            cdk.Stack.of(this).formatArn({
              service: "secretsmanager",
              resource: `secret:aws/transfer/${server.attrServerId}/*`,
            }),
          ],
          actions: ["secretsmanager:GetSecretValue"],
        }),
      ],
    });

    authHandlerPolicy.attachToRole(authHandler.role!);

    const bucket = new s3.Bucket(this, 'bucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: {
        blockPublicAcls: true,
        blockPublicPolicy: true,
        ignorePublicAcls: true,
        restrictPublicBuckets: true,
      },
      versioned: true,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [
        {
          enabled: true,
          expiration: cdk.Duration.days(365),
        },
      ],
    });

    const role = new iam.Role(this, `FtpUserRole`, {
      assumedBy: new iam.ServicePrincipal("transfer.amazonaws.com"),
    });

    const userName = "djenniex";
    const password = "password";

    /*
    Secret Format
    Key - Password
    Example Value - mySup3rS3cr3tPa55w0rd
    Explanation: This password is used for SFTP and FTPS protocols

    Key - Role
    Example Value - arn:aws:iam::xxxxxxxxxxxx:role/AWSTransferAccessRole
    Explanation: Role ARNs for AWS Transfer users. This will define what access the user has to S3

    Optional:
    Key - HomeDirectory
    Example Value: /bucket/home/myhomedirectory
    Explanation: The path to the user home directory. Not valid if HomeDirectoryDetails is used

    Key - HomeDirectoryDetails
    Example Value: [{"Entry": "/", "Target": "/ bucket/home/myhomedirectory"}]
    Explanation: Logical folders mapping template. Not valid if HomeDirectory is used

    Key - PublicKey
    Example Value - ssh rsa public-key
    Explanation: Comma separated list of public SSH keys (up to two keys)

    Key - FTPPassword
    Example Value - mySup3rS3cr3tFTPPa55w0rd
    Explanation: This password is used for the FTP protocol

    Key – AcceptedIpNetwork
    Example Value – 192.168.1.0/24
    Explanation: CIDR range of allowed source IP address for the client
    */
    new sm.Secret(this, `FtpUserSecret`, {
      secretName: `aws/transfer/${serverId}/${userName}`,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          Role: role.roleArn,
          HomeDirectory: `/${bucket.bucketName}`,
          Password: password,
        }),
        generateStringKey: password == null ? "Password" : "Dummy",
        excludePunctuation: true,
      },
    });

    bucket.grantReadWrite(role);
  }
}
