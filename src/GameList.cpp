#include <GameList.h>

#include <cstdlib>
#include <downloader.h>
#include <iostream>

void GameList::updateTitles(TITLE_CATEGORY cat, MCPRegion reg) {
    treeModel = Gtk::ListStore::create(columns);
    treeView->set_model(treeModel);
    for (unsigned int i = 0; i < getTitleEntriesSize(currentCategory); i++)
    {
        if(!(reg & infos[i].region))
            continue;
        char id[128];
        hex(infos[i].tid, 16, id);
        Gtk::TreeModel::Row row = *(treeModel->append());

        row[columns.index] = i;
        row[columns.name] = infos[i].name;
        row[columns.region] = Glib::ustring::format(getFormattedRegion((MCPRegion)infos[i].region));
        row[columns.kind] = Glib::ustring::format(getFormattedKind(infos[i].tid));
        row[columns.titleId] = Glib::ustring::format(id);
    }
}

GameList::GameList(Glib::RefPtr<Gtk::Builder> builder, const TitleEntry *infos)
{
    this->builder = builder;
    this->infos = infos;

    builder->get_widget("gameListWindow", gameListWindow);
    gameListWindow->show();

    builder->get_widget("gamesButton", gamesButton);
    gamesButton->set_active();
    gamesButton->signal_button_press_event().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_button_selected), TITLE_CATEGORY_GAME));

    builder->get_widget("updatesButton", updatesButton);
    updatesButton->signal_button_press_event().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_button_selected), TITLE_CATEGORY_UPDATE));

    builder->get_widget("dlcsButton", dlcsButton);
    dlcsButton->signal_button_press_event().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_button_selected), TITLE_CATEGORY_DLC));

    builder->get_widget("demoButton", demosButton);
    demosButton->signal_button_press_event().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_button_selected), TITLE_CATEGORY_DEMO));

    builder->get_widget("allButton", allButton);
    allButton->signal_button_press_event().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_button_selected), TITLE_CATEGORY_ALL));

    builder->get_widget("japanButton", japanButton);
    japanButton->signal_toggled().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_region_selected), japanButton, MCP_REGION_JAPAN));

    builder->get_widget("usaButton", usaButton);
    usaButton->signal_toggled().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_region_selected), usaButton, MCP_REGION_USA));

    builder->get_widget("europeButton", europeButton);
    europeButton->signal_toggled().connect_notify(sigc::bind(sigc::mem_fun(*this, &GameList::on_region_selected), europeButton, MCP_REGION_EUROPE));

    builder->get_widget("gameTree", treeView);
    treeView->signal_row_activated().connect(sigc::mem_fun(*this, &GameList::on_gamelist_row_activated));

    updateTitles(currentCategory, selectedRegion);

    treeView->append_column("TitleID", columns.titleId);
    treeView->get_column(0)->set_sort_column(columns.titleId);

    treeView->append_column("Kind", columns.kind);

    treeView->append_column("Region", columns.region);

    treeView->append_column("Name", columns.name);
    treeView->get_column(3)->set_sort_column(columns.name);

    // Search for name
    treeView->set_search_column(4);

    // Sort by name by default
    treeModel->set_sort_column(GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID, Gtk::SortType::SORT_ASCENDING);
    treeModel->set_sort_column(4, Gtk::SortType::SORT_ASCENDING);

    treeView->set_search_equal_func(sigc::mem_fun(*this, &GameList::on_search_equal));
}

GameList::~GameList()
{
    
}

void GameList::on_button_selected(GdkEventButton* ev, TITLE_CATEGORY cat) {
    currentCategory = cat;
    infos = getTitleEntries(currentCategory);
    updateTitles(currentCategory, selectedRegion);
    return;
}

void GameList::on_region_selected(Gtk::ToggleButton* button, MCPRegion reg) {
    if (button->get_active())
        selectedRegion |= reg;
    else
        selectedRegion &= ~reg;
    updateTitles(currentCategory, selectedRegion);
    return;
}

void GameList::on_gamelist_row_activated(const Gtk::TreePath& treePath, Gtk::TreeViewColumn* const& column)
{
    Glib::RefPtr<Gtk::TreeSelection> selection = treeView->get_selection();
    Gtk::TreeModel::Row row = *selection->get_selected();

    gameListWindow->set_sensitive(false);
    char selectedTID[128];
    sprintf(selectedTID, "%016llx", infos[row[columns.index]].tid);
    downloadTitle(selectedTID);
    gameListWindow->set_sensitive(true);
}

bool GameList::on_search_equal(const Glib::RefPtr<Gtk::TreeModel>& model, int column, const Glib::ustring& key, const Gtk::TreeModel::iterator& iter)
{
    Gtk::TreeModel::Row row = *iter;

    Glib::ustring name = row[columns.name];
    std::string string_name(name.lowercase());
    std::string string_key(key.lowercase());
    if (string_name.find(string_key) != std::string::npos)
    {
        return false;
    }

    Glib::ustring titleId = row[columns.titleId];
    if (strcmp(titleId.c_str(), key.c_str()) == 0)
    {
        return false;
    }

    return true;
}