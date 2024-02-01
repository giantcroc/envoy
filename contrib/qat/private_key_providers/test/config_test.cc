#include <string>

#include "source/common/common/random_generator.h"
#include "source/extensions/transport_sockets/tls/private_key/private_key_manager_impl.h"

#include "test/common/stats/stat_test_utility.h"
#include "test/mocks/common.h"
#include "test/mocks/server/transport_socket_factory_context.h"
#include "test/mocks/ssl/mocks.h"
#include "test/mocks/thread_local/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/registry.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "contrib/qat/private_key_providers/source/qat_private_key_provider.h"
#include "fake_factory.h"
#include "gtest/gtest.h"

using testing::NiceMock;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace Qat {

envoy::extensions::transport_sockets::tls::v3::PrivateKeyProvider
parsePrivateKeyProviderFromV3Yaml(const std::string& yaml_string) {
  envoy::extensions::transport_sockets::tls::v3::PrivateKeyProvider private_key_provider;
  TestUtility::loadFromYaml(TestEnvironment::substitute(yaml_string), private_key_provider);
  return private_key_provider;
}

class FakeSingletonManager : public Singleton::Manager {
public:
  FakeSingletonManager(LibQatCryptoSharedPtr libqat) : libqat_(libqat) {}
  Singleton::InstanceSharedPtr get(const std::string&, Singleton::SingletonFactoryCb,
                                   bool) override {
    return std::make_shared<QatManager>(libqat_);
  }

private:
  LibQatCryptoSharedPtr libqat_;
};

class QatConfigTest : public Event::TestUsingSimulatedTime, public testing::Test {
public:
  QatConfigTest()
      : api_(Api::createApiForTest(store_, time_system_)),
        libqat_(std::make_shared<FakeLibQatCryptoImpl>()), fsm_(libqat_) {
    ON_CALL(factory_context_.server_context_, api()).WillByDefault(ReturnRef(*api_));
    ON_CALL(factory_context_, sslContextManager()).WillByDefault(ReturnRef(context_manager_));
    ON_CALL(context_manager_, privateKeyMethodManager())
        .WillByDefault(ReturnRef(private_key_method_manager_));
    ON_CALL(factory_context_.server_context_, singletonManager()).WillByDefault(ReturnRef(fsm_));
  }

  Ssl::PrivateKeyMethodProviderSharedPtr createWithConfig(std::string yaml,
                                                          std::string private_key = "") {
    FakeQatPrivateKeyMethodFactory qat_factory;
    Registry::InjectFactory<Ssl::PrivateKeyMethodProviderInstanceFactory>
        qat_private_key_method_factory(qat_factory);

    return factory_context_.sslContextManager()
        .privateKeyMethodManager()
        .createPrivateKeyMethodProvider(parsePrivateKeyProviderFromV3Yaml(yaml), private_key,
                                        factory_context_);
  }

  Event::SimulatedTimeSystem time_system_;
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> factory_context_;
  Stats::IsolatedStoreImpl store_;
  Api::ApiPtr api_;
  NiceMock<Ssl::MockContextManager> context_manager_;
  TransportSockets::Tls::PrivateKeyMethodManagerImpl private_key_method_manager_;
  std::shared_ptr<FakeLibQatCryptoImpl> libqat_;
  FakeSingletonManager fsm_;
};

TEST_F(QatConfigTest, CreateRsa1024) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/rsa-1024.pem" }
)EOF";

  Ssl::PrivateKeyMethodProviderSharedPtr provider = createWithConfig(yaml);
  EXPECT_NE(nullptr, provider);
  EXPECT_EQ(false, provider->checkFips());
  EXPECT_EQ(provider->isAvailable(), true);
  Ssl::BoringSslPrivateKeyMethodSharedPtr method = provider->getBoringSslPrivateKeyMethod();
  EXPECT_NE(nullptr, method);
}

TEST_F(QatConfigTest, CreateInputRsa1024) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
)EOF";

  const std::string private_key = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCahx0RdJwYtXtBNI98b+xN28HmcEzRMcByJZ6FHpDnTOXmUKpF
olHYlypZ5lLSHIuPJAcUk33iXpOqJQLBv8wUR0EPUXAnsZosbhJtAlxV4BIVj0QY
3RiLaZ1QGzXS4rNiLFwJDPwVnG9tKZlRpmCmYrLb5lhBEfiG8Ug7rjKVUQIDAQAB
AoGAbTbXXZHsDS6e6UvrqYg1HCYYWfS+5g9is4pRCka7JS7dQbV7UnHRpOHaBeXa
XTPdkxJkiq9fhlFPzi4QT71tz0IQ20b+MtgqkJkMDkLhUYYN17fMtNvtTQnVmxNk
a5k9HcAkp00qPF8d8i4/quRTulRHnNbip8wpeaqRWbsrGxECQQDIng+8oXf2B51i
hYRnyLQysSRoqpFE9C2XDCrA7+e4G8UvdFPS9R9XBoOgFZvf/kjMCJxc68/15XfX
yvlHc/PNAkEAxS/Tv5PMYGYOvCiYBxPPFvOIb025iCKjA04YHDbm8LBHoRLXw+R6
DWYH9iyKB5ZJfiMTjn0wp/VharTzwwtrlQJBAI4EputH+x4mAdpO3o6B3F7OXBHk
PXZszSFSsalnq8f/kLWpSfXbJNZ8fA2FfpUw8+PMbLSzEsLmMNKIk7NreDkCQQDB
EuV4zhTtxsBiyDSjqWe6h1Zt9WLWw2NuFwdQiQlzXoekVbji3FIN0Hu3NUEp0KPB
WEML39TGgGOUgf20WvhJAkBQ4jNgi2d8y/2vlh4B3wKsI1hJvZPjkqh66KH7OyF4
Wa8lQ1gBgajTYocZkmIcf2dkrNArmMl2ozWJrFY9vSDs
-----END RSA PRIVATE KEY-----
)EOF";

  Ssl::PrivateKeyMethodProviderSharedPtr provider = createWithConfig(yaml, private_key);
  EXPECT_NE(nullptr, provider);
  EXPECT_EQ(provider->isAvailable(), true);
}

TEST_F(QatConfigTest, CreateRsa2048) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/rsa-2048.pem" }
)EOF";

  Ssl::PrivateKeyMethodProviderSharedPtr provider = createWithConfig(yaml);
  EXPECT_NE(nullptr, provider);
  EXPECT_EQ(provider->isAvailable(), true);
}

TEST_F(QatConfigTest, CreateRsa3072) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/rsa-3072.pem" }
)EOF";

  Ssl::PrivateKeyMethodProviderSharedPtr provider = createWithConfig(yaml);
  EXPECT_NE(nullptr, provider);
  EXPECT_EQ(provider->isAvailable(), true);
}

TEST_F(QatConfigTest, CreateRsa4096) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/rsa-4096.pem" }
)EOF";

  Ssl::PrivateKeyMethodProviderSharedPtr provider = createWithConfig(yaml);
  EXPECT_NE(nullptr, provider);
  EXPECT_EQ(provider->isAvailable(), true);
}

TEST_F(QatConfigTest, CreateEcdsaP256) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/ecdsa-p256.pem" }
)EOF";

  Ssl::PrivateKeyMethodProviderSharedPtr provider = createWithConfig(yaml);
  EXPECT_NE(nullptr, provider);
  EXPECT_EQ(provider->isAvailable(), false);
}

TEST_F(QatConfigTest, CreateMissingPrivateKeyFile) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/missing.pem" }
)EOF";

  EXPECT_THROW(createWithConfig(yaml), EnvoyException);
}

TEST_F(QatConfigTest, CreateMissingKey) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0.02s
        )EOF";

  EXPECT_THROW(createWithConfig(yaml), EnvoyException);
}

TEST_F(QatConfigTest, CreateMissingPollDelay) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/rsa-4096.pem" }
        )EOF";

  EXPECT_THROW_WITH_REGEX(createWithConfig(yaml), EnvoyException,
                          "Proto constraint validation failed");
}

TEST_F(QatConfigTest, CreateZeroPollDelay) {
  const std::string yaml = R"EOF(
      provider_name: qat
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.private_key_providers.qat.v3alpha.QatPrivateKeyMethodConfig
        poll_delay: 0s
        private_key: { "filename": "{{ test_rundir }}/contrib/qat/private_key_providers/test/test_data/rsa-4096.pem" }
        )EOF";

  EXPECT_THROW_WITH_REGEX(createWithConfig(yaml), EnvoyException,
                          "Proto constraint validation failed");
}

} // namespace Qat
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
