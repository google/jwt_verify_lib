#include "jwt_verify_lib/jwks.h"

#include <fstream>

#include "absl/strings/str_cat.h"
#include "google/protobuf/text_format.h"

#include "gtest/gtest.h"

#include "test/fuzz/jwt_verify_lib_fuzz_input.pb.h"

namespace google {
namespace jwt_verify {
namespace {

const absl::string_view kRunfilesDir = std::getenv("TEST_SRCDIR");
const absl::string_view kWorkingDir = std::getenv("TEST_WORKSPACE");
constexpr absl::string_view kDataDir =
    "test/fuzz/corpus/jwt_verify_lib_fuzz_test";

std::string ReadTestBaseline(const std::string& input_file_name) {
  // Must reference testdata with an absolute path.
  std::string file_name = absl::StrCat(kRunfilesDir, "/", kWorkingDir, "/",
                                       kDataDir, "/", input_file_name);

  std::string contents;
  std::ifstream input_file;
  input_file.open(file_name, std::ifstream::in | std::ifstream::binary);
  EXPECT_TRUE(input_file.is_open()) << file_name;
  input_file.seekg(0, std::ios::end);
  contents.reserve(input_file.tellg());
  input_file.seekg(0, std::ios::beg);
  contents.assign((std::istreambuf_iterator<char>(input_file)),
                  (std::istreambuf_iterator<char>()));

  return contents;
}

// This test verifies the "jwks" field in corpus files are correct.
// They can be parsed correctly.
TEST(JwksParseTest, FuzzTestJwksCorpusFile) {
  std::vector<std::string> files = {"jwks_ec.txt", "jwks_rsa.txt",
                                    "jwks_hmac.txt", "jwks_okp.txt",
                                    "jwks_x509.txt"};
  for (const auto& file : files) {
    const std::string txt = ReadTestBaseline(file);
    FuzzInput input;
    EXPECT_TRUE(google::protobuf::TextFormat::ParseFromString(txt, &input));

    auto jwks = Jwks::createFrom(input.jwks(), Jwks::JWKS);
    EXPECT_EQ(jwks->getStatus(), Status::Ok) << "failed corpus_file: " << file;
  }
}

TEST(JwksParseTest, FuzzTestPemCorpusFile) {
  std::vector<std::string> files = {"jwks_pem.txt"};
  for (const auto& file : files) {
    const std::string txt = ReadTestBaseline(file);
    FuzzInput input;
    EXPECT_TRUE(google::protobuf::TextFormat::ParseFromString(txt, &input));

    auto jwks = Jwks::createFrom(input.jwks(), Jwks::PEM);
    EXPECT_EQ(jwks->getStatus(), Status::Ok) << "failed corpus_file: " << file;
  }
}

}  // namespace
}  // namespace jwt_verify
}  // namespace google
