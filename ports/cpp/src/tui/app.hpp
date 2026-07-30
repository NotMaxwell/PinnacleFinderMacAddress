#pragma once
// ncurses front-end. Terminal-UI equivalent of the original egui/eframe GUI.

namespace pf {

// Initialise ncurses, run the event loop until the user quits, then tear down.
int run_tui();

} // namespace pf
