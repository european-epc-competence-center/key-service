import { formatSigningError } from "./format-signing-error";
import { errors as joseErrors } from "jose";

describe("formatSigningError", () => {
  it("formats jsonld JsonLdEvent-style details", () => {
    const error = Object.assign(new Error("The property is not supported."), {
      details: {
        event: {
          code: "invalid property",
          message:
            "Dropping property that did not expand into an absolute IRI or keyword.",
          details: { property: "keyAuthorization" },
        },
      },
    });

    const message = formatSigningError(error);

    expect(message).toContain("Failed to sign:");
    expect(message).not.toContain("undefined");
    expect(message).not.toContain("[object Object]");
    expect(message).toContain("keyAuthorization");
    expect(message).toContain(
      "Dropping property that did not expand into an absolute IRI or keyword."
    );
  });

  it("formats jsonld InvalidUrl-style details", () => {
    const error = Object.assign(
      new Error(
        'URL "https://ref.gs1.org/missing" could not be dereferenced: Not Found'
      ),
      {
        details: {
          code: "loading document failed",
          url: "https://ref.gs1.org/missing",
          httpStatusCode: 404,
        },
      }
    );

    const message = formatSigningError(error);

    expect(message).toContain("could not be dereferenced");
    expect(message).toContain("https://ref.gs1.org/missing");
    expect(message).not.toContain("[object Object]");
  });

  it("returns a generic message for non-Error values", () => {
    expect(formatSigningError("something went wrong")).toBe(
      "Failed to sign: Unknown error"
    );
  });

  it("uses error.message when no details are present", () => {
    const error = new Error("Signing suite mismatch");

    expect(formatSigningError(error)).toBe(
      "Failed to sign: Signing suite mismatch"
    );
  });

  it("formats jose JWSInvalid errors with code in details", () => {
    const error = new joseErrors.JWSInvalid("Invalid Compact JWS");

    const message = formatSigningError(error);

    expect(message).toContain("Failed to sign: Invalid Compact JWS");
    expect(message).toContain("ERR_JWS_INVALID");
    expect(message).not.toContain("[object Object]");
  });

  it("formats jose JWTClaimValidationFailed with claim and reason", () => {
    const error = new joseErrors.JWTClaimValidationFailed(
      '"exp" claim timestamp check failed',
      { sub: "holder-did" },
      "exp",
      "check_failed",
    );

    const message = formatSigningError(error);

    expect(message).toContain('"exp" claim timestamp check failed');
    expect(message).toContain("ERR_JWT_CLAIM_VALIDATION_FAILED");
    expect(message).toContain("exp");
    expect(message).toContain("check_failed");
    expect(message).not.toContain("[object Object]");
    expect(message).not.toContain("holder-did");
  });

  it("formats jose errors with an Error cause", () => {
    const cause = new TypeError("underlying crypto failure");
    const error = new joseErrors.JWSSignatureVerificationFailed(
      "signature verification failed",
      { cause },
    );

    const message = formatSigningError(error);

    expect(message).toContain("signature verification failed");
    expect(message).toContain("TypeError: underlying crypto failure");
    expect(message).not.toContain("[object Object]");
  });
});
