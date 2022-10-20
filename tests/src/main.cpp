#include <signal.h>

#include "UnitTest.hpp"

#define VERSION "0.1"
#include "sys/Cli.hpp"

using namespace test;

void segfault(int a) { API_ASSERT(false); }

int main(int argc, char *argv[]) {
  sys::Cli cli(argc, argv);

#if defined __link
  signal(11, segfault);
#endif


  {
    auto scope
      = Test::Scope<printer::Printer>(test::Test::Initialize()
                                              .set_name(cli.get_name())
                                              .set_version(VERSION)
                                              .set_git_hash(CMSDK_GIT_HASH));
    Test::printer().set_verbose_level(cli.get_option("verbose"));

    UnitTest(cli.get_name()).execute(cli);
  }
  exit(test::Test::final_result() == false);

  return 0;
}
