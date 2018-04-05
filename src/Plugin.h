// Copyright 2018 Reservoir Labs


#ifndef BRO_PLUGIN_RLABS_FIX_SBE
#define BRO_PLUGIN_RLABS_FIX_SBE

#include <plugin/Plugin.h>

namespace plugin {
namespace RLABS_FIX_SOFH {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
