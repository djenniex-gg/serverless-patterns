import * as lambda from "aws-lambda";
import * as ip from "ipaddr.js";
import { getSecret } from "./secrets-provider";

type Response = Record<string, string | string[]>;

export const handler = async (event: lambda.APIGatewayProxyEvent): Promise<lambda.APIGatewayProxyResult> => {
  console.log(event);
  try {
    const response: Response = await handlerHelper(event);
    return {
      statusCode: 200,
      body: JSON.stringify(response),
    };
  } catch (err) {
    console.error("Error", err);

    if (err instanceof Error) {
      throw new Error(err.message);
    }

    throw new Error("Unknown error occured");
  }
};

const handlerHelper = async (event: lambda.APIGatewayProxyEvent): Promise<Response> => {
  console.log(event);

  if (!event.pathParameters) {
    throw new Error("event does not contain pathParameters");
  }

  for (const parameter of ["serverId", "username"]) {
    if (!event.pathParameters[parameter]) {
      throw new Error(`event does not contain pathParameters.${parameter}`);
    }
  }

  if (!event.requestContext.identity.sourceIp) {
    throw new Error("event does not contain sourceIp");
  }

  const inputServerId: string = event.pathParameters.serverId!;
  const inputUsername: string = event.pathParameters.username!;
  const inputProtocol: string = event.queryStringParameters?.protocol || "SSH";
  const inputSourceIp: string = event.requestContext.identity.sourceIp;
  const inputPassword: string = event.headers.Password || "";

  console.log(
    `ServerId: ${inputServerId}, Username: ${inputUsername}, Protocol: ${inputProtocol}, SourceIp: ${inputSourceIp}`,
  );

  // Check for password and set authentication type appropriately. No password means SSH auth
  console.log("Start User Authentication Flow");
  console.log("Assuming SSH authentication");
  let authenticationType: string = "SSH";
  if (inputPassword !== "") {
    console.log("Using PASSWORD authentication");
    authenticationType = "PASSWORD";
  } else {
    if (inputProtocol === "FTP" || inputProtocol === "FTPS") {
      throw new Error("Empty password not allowed for FTP/S");
    }
  }

  // Retrieve our user details from the secret. For all key-value pairs stored in SecretManager,
  // checking the protocol-specified secret first, then use generic ones.
  // e.g. If SFTPPassword and Password both exists, will be using SFTPPassword for authentication
  const secret: string | undefined = (await getSecret(`aws/transfer/${inputServerId}/${inputUsername}`)).SecretString;

  if (!secret) {
    throw new Error("No secret found");
  }

  const secretDict: Record<string, string> = JSON.parse(secret) as Record<string, string>;
  // Run our password checks
  const user_authenticated: boolean = authenticateUser(authenticationType, secretDict, inputPassword, inputProtocol);
  // Run sourceIp checks
  const ip_match: boolean = checkIpaddress(secretDict, inputSourceIp, inputProtocol);

  if (user_authenticated && ip_match) {
    console.log(`User authenticated, calling buildResponse with: ${authenticationType}`);
    return buildResponse(secretDict, authenticationType, inputProtocol);
  }

  throw new Error("User failed authentication.");
};

const lookup = (secretDict: Record<string, string>, key: string, inputProtocol: string): string | undefined => {
  if (secretDict[inputProtocol + key]) {
    console.log(`Found protocol-specified ${key}`);
    return secretDict[inputProtocol + key];
  }
  return secretDict[key];
};

const checkIpaddress = (secretDict: Record<string, string>, inputSourceIp: string, inputProtocol: string): boolean => {
  const acceptedIpNetwork: string | undefined = lookup(secretDict, "AcceptedIpNetwork", inputProtocol);
  if (!acceptedIpNetwork) {
    // No IP provided so skip checks
    console.log("No IP range provided - Skip IP check");
    return true;
  }

  const net: [ip.IPv4 | ip.IPv6, number] = ip.parseCIDR(acceptedIpNetwork);
  if (ip.parse(inputSourceIp).match(net)) {
    console.log("Source IP address match");
    return true;
  }

  console.log("Source IP address not in range");
  return false;
};

const authenticateUser = (
  authType: string,
  secretDict: Record<string, string>,
  inputPassword: string,
  inputProtocol: string,
): boolean => {
  if (authType === "SSH") {
    // Place for additional checks in future
    console.log("Skip password check as SSH login request");
    return true;
  }

  // authType could only be SSH or PASSWORD
  const password: string | undefined = lookup(secretDict, "Password", inputProtocol);
  if (!password) {
    console.log("Unable to authenticate user - No field match in Secret for password");
    return false;
  }

  if (inputPassword === password) {
    return true;
  }

  console.log("Unable to authenticate user - Incoming password does not match stored");
  return false;
};

const buildResponse = (secretDict: Record<string, string>, authType: string, inputProtocol: string): Response => {
  const responseData: Response = {};
  // Check for each key value pair. These are required so set to empty string if missing
  const role: string | undefined = lookup(secretDict, "Role", inputProtocol);
  if (role) {
    responseData["Role"] = role;
  } else {
    console.log("No field match for role - Set empty string in response");
    responseData["Role"] = "";
  }

  // These are optional so ignore if not present
  const policy: string | undefined = lookup(secretDict, "Policy", inputProtocol);
  if (policy) {
    responseData["Policy"] = policy;
  }

  // External Auth providers support chroot and virtual folder assignments so we'll check for that
  const homeDirectoryDetails: string | undefined = lookup(secretDict, "HomeDirectoryDetails", inputProtocol);
  if (homeDirectoryDetails) {
    console.log(
      "HomeDirectoryDetails found - Applying setting for virtual folders - Note: Cannot be used in conjunction with key: HomeDirectory",
    );
    responseData["HomeDirectoryDetails"] = homeDirectoryDetails;
    // If we have a virtual folder setup then we also need to set HomeDirectoryType to "Logical"
    console.log("Setting HomeDirectoryType to LOGICAL");
    responseData["HomeDirectoryType"] = "LOGICAL";
  }

  // Note that HomeDirectory and HomeDirectoryDetails / Logical mode
  // can't be used together but we're not checking for this
  const homeDirectory: string | undefined = lookup(secretDict, "HomeDirectory", inputProtocol);
  if (homeDirectory) {
    console.log("HomeDirectory found - Note: Cannot be used in conjunction with key: HomeDirectoryDetails");
    responseData["HomeDirectory"] = homeDirectory;
  }

  if (authType === "SSH") {
    const publicKey: string | undefined = lookup(secretDict, "PublicKey", inputProtocol);
    if (!publicKey) {
      // SSH Auth Flow - We don't have keys so we can't help
      throw new Error("Unable to authenticate user - No public keys found");
    }
    responseData["PublicKeys"] = [publicKey];
  }

  return responseData;
};
