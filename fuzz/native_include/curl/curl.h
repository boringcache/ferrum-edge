#ifndef FERRUM_FUZZ_DISABLED_LIBRDKAFKA_CURL_H
#define FERRUM_FUZZ_DISABLED_LIBRDKAFKA_CURL_H

/*
 * librdkafka 2.12.1's rdkafka_conf.c includes <curl/curl.h> under
 * `#ifdef WITH_OAUTHBEARER_OIDC`, although its CMake build defines the
 * disabled feature as `WITH_OAUTHBEARER_OIDC=0`. Every code path that uses
 * curl types or functions is correctly guarded by `#if WITH_OAUTHBEARER_OIDC`.
 *
 * The fuzz workspace builds Ferrum Edge with that feature disabled. This
 * intentionally empty header only satisfies the erroneous include; it must
 * not grow into a curl API shim.
 */

#endif
