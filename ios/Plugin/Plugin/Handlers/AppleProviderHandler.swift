import Foundation
import Capacitor
import AuthenticationServices
import CryptoKit
import FirebaseCore
import FirebaseAuth


class AppleProviderHandler: NSObject, ProviderHandler {
    var plugin: CapacitorFirebaseAuth? = nil
    // Unhashed nonce
    fileprivate var currentNonce: String?
    // Info
    fileprivate var user: String?
    fileprivate var email: String?
    fileprivate var fullName: String?
    fileprivate var identityToken: String?
    fileprivate var authorizationCode: String?

    func initialize(plugin: CapacitorFirebaseAuth) {
        print("Initializing Apple Provider Handler")
        self.plugin = plugin
    }

    // @available(iOS 13, *)
    func signIn(call: CAPPluginCall) {
        if #available(iOS 13.0, *) {
            let nonce = randomNonceString()
            currentNonce = nonce
            let appleIDProvider = ASAuthorizationAppleIDProvider()
            let request = appleIDProvider.createRequest()
            request.requestedScopes = [.fullName, .email]

            let authorizationController = ASAuthorizationController(authorizationRequests: [request])
            authorizationController.delegate = self
            authorizationController.performRequests()
        } else {
            call.reject("Sign in with Apple is available on iOS 13.0+ only.")
        }
    }

    func isAuthenticated() -> Bool {
        // TODO
        return false
    }

    func fillResult(data: PluginResultData) -> PluginResultData {
        var jsResult: PluginResultData = [:]
        data.map { (key, value) in
            jsResult[key] = value
        }

        // Attach values from the auth result from Appl sign-in
        jsResult["user"] = self.user
        jsResult["email"] = self.email
        jsResult["fullName"] = self.fullName
        jsResult["identityToken"] = self.identityToken
        jsResult["authorizationCode"] = self.authorizationCode
        jsResult["nonce"] = self.currentNonce
        
        return jsResult
    }

    func signOut(){
        // TODO
        // Needed? Since apple doesn't provide a logout method?
    }

    @available(iOS 13, *)
    private func sha256(_ input: String) -> String {
        let inputData = Data(input.utf8)
        let hashedData = SHA256.hash(data: inputData)
        let hashString = hashedData.compactMap {
            return String(format: "%02x", $0)
        }.joined()

        return hashString
    }

    // Adapted from https://auth0.com/docs/api-auth/tutorials/nonce#generate-a-cryptographically-random-nonce
    private func randomNonceString(length: Int = 32) -> String {
        precondition(length > 0)
        let charset: Array<Character> =
            Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
        var result = ""
        var remainingLength = length

        while remainingLength > 0 {
            let randoms: [UInt8] = (0 ..< 16).map { _ in
                var random: UInt8 = 0
                let errorCode = SecRandomCopyBytes(kSecRandomDefault, 1, &random)
                if errorCode != errSecSuccess {
                    fatalError("Unable to generate nonce. SecRandomCopyBytes failed with OSStatus \(errorCode)")
                }
                return random
            }

            randoms.forEach { random in
                if length == 0 {
                    return
                }

                if random < charset.count {
                    result.append(charset[Int(random)])
                    remainingLength -= 1
                }
            }
        }

        return result
    }
}

@available(iOS 13.0, *)
extension AppleProviderHandler: ASAuthorizationControllerDelegate {

  func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    if let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential {
      guard let nonce = currentNonce else {
        fatalError("Invalid state: A login callback was received, but no login request was sent.")
      }
      guard let appleIDToken = appleIDCredential.identityToken else {
        print("Unable to fetch identity token")
        return
      }
      guard let idTokenString = String(data: appleIDToken, encoding: .utf8) else {
        print("Unable to serialize token string from data: \(appleIDToken.debugDescription)")
        return
      }

      let givenName = appleIDCredential.fullName?.givenName ?? ""

      let familyName = appleIDCredential.fullName?.familyName ?? ""

      self.user = appleIDCredential.user
      self.email = appleIDCredential.email
      self.fullName = givenName + " " + familyName
      self.identityToken = String(data: appleIDCredential.identityToken!, encoding: .utf8)
      self.authorizationCode = String(data: appleIDCredential.authorizationCode!, encoding: .utf8)

      // Initialize a Firebase credential.
      let credential = OAuthProvider.credential(withProviderID: "apple.com",
                                                idToken: idTokenString,
                                                rawNonce: nonce)

      // Sign in with Firebase (using either the native layer or web layer depending upon values passed in from capacitor config)
      self.plugin?.handleAuthCredentials(credential: credential)
    }
  }
}

  @available(iOS 13.0, *)
  func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
    // Handle error.
    print("Sign in with Apple errored: \(error)")
  }
