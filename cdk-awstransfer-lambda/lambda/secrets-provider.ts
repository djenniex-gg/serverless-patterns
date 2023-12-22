const AWS_SECRETS_EXTENTION_HTTP_PORT = process.env.PARAMETERS_SECRETS_EXTENSION_HTTP_PORT || 2773;
const AWS_SECRETS_EXTENTION_SERVER_ENDPOINT = `http://localhost:${AWS_SECRETS_EXTENTION_HTTP_PORT}/secretsmanager/get?secretId=`;

export interface GetSecretResult {
  ARN: string;
  CreatedDate: string;
  Name: string;
  SecretBinary: string | undefined;
  SecretString: string | undefined;
  VersionId: string;
  VersionStages: Array<string>;
  ResultMetadata: unknown;
}

/**
 * Get the secret based on the secret name
 *
 * @param secretId string
 * @returns string secret value
 * @throws Error if the request fails or the secret value is empty.
 */
export async function getSecret(secretId: string): Promise<GetSecretResult> {
  const url = `${AWS_SECRETS_EXTENTION_SERVER_ENDPOINT}${secretId}`;
  const response = await fetch(url, {
    headers: {
      'X-Aws-Parameters-Secrets-Token': process.env.AWS_SESSION_TOKEN!,
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch secret ${secretId}. Response status: ${response.status}`);
  }

  return (await response.json()) as GetSecretResult;
};
