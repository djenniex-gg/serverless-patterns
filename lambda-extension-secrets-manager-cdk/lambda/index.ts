const AWS_SECRETS_EXTENTION_HTTP_PORT =
  process.env.PARAMETERS_SECRETS_EXTENSION_HTTP_PORT || 2773;
const AWS_SECRETS_EXTENTION_SERVER_ENDPOINT = `http://localhost:${AWS_SECRETS_EXTENTION_HTTP_PORT}/secretsmanager/get?secretId=`;

export interface GetSecretResult {
  ARN: string;
  CreatedDate: string;
  Name: string;
  SecretBinary: string | null;
  SecretString: string | null;
  VersionId: string;
  VersionStages: Array<string>;
  ResultMetadata: unknown;
}

export const handler = async (): Promise<GetSecretResult> => {
  const secretId = process.env.SECRET_ID;
  const url = `${AWS_SECRETS_EXTENTION_SERVER_ENDPOINT}${secretId}`;

  const response = await fetch(url, {
    headers: {
      "X-Aws-Parameters-Secrets-Token": process.env.AWS_SESSION_TOKEN!,
    },
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch secret ${secretId}. Response status: ${response.status}`,
    );
  }

  return (await response.json()) as GetSecretResult;
};
