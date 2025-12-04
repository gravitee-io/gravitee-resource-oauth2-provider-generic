# [4.3.0-alpha.1](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/4.2.0...4.3.0-alpha.1) (2025-12-04)


### Features

* add the OAuth2GenericResource.getProtectedResourceMetadata() method ([11d719d](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/11d719d22dcd3ca038ad5a483b81e469129e0cb7))

# [4.2.0](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/4.1.0...4.2.0) (2025-11-24)


### Features

* make OAuth2 resource HTTP client timeouts configurable ([900a647](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/900a647bb95aef5d251537be89326e0cbc9ecf45))

# [4.1.0](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/4.0.3...4.1.0) (2025-11-19)


### Features

* allow to configure max concurrent connections ([e5ceb90](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/e5ceb9034eb28dc94f35f79e9c5e9bdf97506f6b))

## [4.0.3](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/4.0.2...4.0.3) (2025-06-26)


### Bug Fixes

* **deps:** bump gravitee-apim-bom to 4.6.14 ([8b1aff5](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/8b1aff5f0066263002b8b73a355e6315ee787613))

## [4.0.2](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/4.0.1...4.0.2) (2025-01-17)


### Bug Fixes

* udpate README and schema form for EL and secrets support ([1f45f1b](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/1f45f1beb044e20485e4790ac3bf014fa918db67))

## [4.0.1](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/4.0.0...4.0.1) (2025-01-09)


### Bug Fixes

* add clientId as a secret value, fix README ([4dfdbd7](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/4dfdbd75265028a3525dd2e2b9a866fbf638fd9d))

# [4.0.0](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/3.0.0...4.0.0) (2025-01-09)


### Bug Fixes

* adapt ci config to build preleases ([c3c419b](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/c3c419b64b57273a274a17bb7f900ba63feeb5ec))
* retry ci ([0b6f8bb](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/0b6f8bbf0f9f79c855b8db0bae3f5e0ddaf15351))


### chore

* rework pom management ([04d29fe](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/04d29fec3632af0da53ebeafb86f9093a395eeec))


### Features

* add EL support via annotation processor and secrets ([8e27b6a](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/8e27b6abda5cb9c43e1c505e1823532a3967e733))


### BREAKING CHANGES

* requires APIM 4.6.x that provides secret-api 1.0.0 and gravitee-node 7.0.0

# [4.0.0-alpha.2](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/4.0.0-alpha.1...4.0.0-alpha.2) (2025-01-09)


### Bug Fixes

* adapt ci config to build preleases ([afcb358](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/afcb3580025b819f8a458805490371b5548d4eb7))

# [4.0.0-alpha.1](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/3.1.0-alpha.1...4.0.0-alpha.1) (2025-01-07)


### chore

* rework pom management ([8c06b7c](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/8c06b7c154ae9d10c7ca32e27edfe68305506b4d))


### BREAKING CHANGES

* requires APIM 4.6.x that provides secret-api 1.0.0 and gravitee-node 7.0.0

# [3.1.0-alpha.1](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/3.0.0...3.1.0-alpha.1) (2025-01-07)


### Features

* add EL support via annotation processor and secrets ([eabed38](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/eabed382515c8aacda9cd116b6d93ed07269e0c0))

# [3.0.0](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/2.1.0...3.0.0) (2024-12-16)


### Bug Fixes

* lint after gravitee parent update ([62197c6](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/62197c6f28b11c3e9495c4b91a6c874b68976f74))
* use VertxProxyOptionsUtils from gravitee node ([1e67741](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/1e67741d387c51b780404e48be8cf9370e7bd86e))


### BREAKING CHANGES

* require APIM 4.4.x

# [2.1.0](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/2.0.2...2.1.0) (2024-07-11)


### Features

* rework schema-form to use new GioJsonSchema Ui component ([4b887eb](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/4b887ebc72c633f2332647b20c97383c2bb67115))

## [2.0.2](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/2.0.1...2.0.2) (2023-11-23)


### Bug Fixes

* use a throwable in the Oauth2Response on technical error for introspection ([4d3a54f](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/4d3a54fc9a4ee00848f39264b4eacb3609f687a7))
* use a throwable in the UserInfoResponse on technical error for userInfo ([58c635a](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/58c635afebb04877a35f6acdb7022f7eefdd00af))

## [2.0.1](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/2.0.0...2.0.1) (2023-10-03)


### Bug Fixes

* handle customer userClaim ([3ef2136](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/3ef213644cc2ac3ec72c5960d986de56653d58e4))

# [2.0.0](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/1.16.2...2.0.0) (2022-05-24)


### Code Refactoring

* use common system proxy options factory ([0f04e1b](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/0f04e1bcfea3ed624b44333ce47f09f765935ba0))


### BREAKING CHANGES

* this version requires APIM in version 3.18 and upper

## [1.16.2](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/compare/1.16.1...1.16.2) (2022-05-24)


### Bug Fixes

* add system proxy support ([b0861ff](https://github.com/gravitee-io/gravitee-resource-oauth2-provider-generic/commit/b0861ff8996f216ffa7398e393fb6207583fb161))
