// Copyright 2018 Reservoir Labs

#include "plugin/Plugin.h"

#include "FIX_SBE.h"

namespace plugin {
namespace Bro_FIX_SOFH {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("FIX_SOFH",
		             ::analyzer::FIX_SOFH::FIX_SBE_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Bro::FIX_SOFH";
		config.description = "Financial Information eXchange / SOFH analyzer";
                config.version.major = 1;
                config.version.minor = 0;
		return config;
		}
} plugin;

}
}
