jQuery(document).ready(function ($) {
  "use strict";

  // Inicializace Security Guardian admin rozhraní
  const SecurityGuardian = {
    init: function () {
      this.bindEvents();
      this.initTooltips();
      this.initSearchFilter();
      this.initBulkActions();
      this.showWelcomeMessage();
    },

    bindEvents: function () {
      // Toggle všech checkboxů
      $("#wpsg-select-all").on("change", this.toggleAllPlugins);

      // Hledání pluginů
      $("#wpsg-search").on("input", this.filterPlugins);

      // Hromadné akce
      $("#wpsg-bulk-enable").on("click", this.bulkEnable);
      $("#wpsg-bulk-disable").on("click", this.bulkDisable);

      // Export/Import nastavení
      $("#wpsg-export").on("click", this.exportSettings);
      $("#wpsg-import").on("change", this.importSettings);

      // Potvrzení před odesláním formuláře
      //$("form").on("submit", this.confirmSubmit);

      // Živé aktualizace statistik
      $('input[name="whitelist_plugins[]"]').on("change", this.updateStats);

      // Animace tlačítek
      $(".wpsg-button").on("mouseenter mouseleave", this.animateButton);
    },

    toggleAllPlugins: function () {
      const isChecked = $(this).is(":checked");
      $('input[name="whitelist_plugins[]"]:not(:disabled)').prop(
        "checked",
        isChecked,
      );
      SecurityGuardian.updateStats();
    },

    filterPlugins: function () {
      const searchTerm = $(this).val().toLowerCase();

      $(".wpsg-plugin-item").each(function () {
        const pluginName = $(this).find(".plugin-name").text().toLowerCase();
        const pluginDesc = $(this)
          .find(".plugin-description")
          .text()
          .toLowerCase();
        const pluginPath = $(this).find(".plugin-path").text().toLowerCase();

        if (
          pluginName.includes(searchTerm) ||
          pluginDesc.includes(searchTerm) ||
          pluginPath.includes(searchTerm)
        ) {
          $(this).slideDown(200);
        } else {
          $(this).slideUp(200);
        }
      });
    },

    bulkEnable: function (e) {
      e.preventDefault();
      $(
        '.wpsg-plugin-item:visible input[name="whitelist_plugins[]"]:not(:disabled)',
      ).prop("checked", true);
      SecurityGuardian.updateStats();
      SecurityGuardian.showNotification(
        "Všechny viditelné pluginy byly povoleny",
        "success",
      );
    },

    bulkDisable: function (e) {
      e.preventDefault();
      $(
        '.wpsg-plugin-item:visible input[name="whitelist_plugins[]"]:not(:disabled)',
      ).prop("checked", false);
      SecurityGuardian.updateStats();
      SecurityGuardian.showNotification(
        "Všechny viditelné pluginy byly zakázány",
        "warning",
      );
    },

    updateStats: function () {
      const totalPlugins = $('input[name="whitelist_plugins[]"]').length;
      const enabledPlugins = $(
        'input[name="whitelist_plugins[]"]:checked',
      ).length;
      const blockedPlugins = totalPlugins - enabledPlugins;

      $("#wpsg-stat-total").text(totalPlugins);
      $("#wpsg-stat-enabled").text(enabledPlugins);
      $("#wpsg-stat-blocked").text(blockedPlugins);

      // Animované čísla
      SecurityGuardian.animateNumber("#wpsg-stat-enabled", enabledPlugins);
      SecurityGuardian.animateNumber("#wpsg-stat-blocked", blockedPlugins);
    },

    animateNumber: function (selector, targetNumber) {
      const $element = $(selector);
      const currentNumber = parseInt($element.text()) || 0;

      $({ number: currentNumber }).animate(
        { number: targetNumber },
        {
          duration: 500,
          easing: "swing",
          step: function () {
            $element.text(Math.ceil(this.number));
          },
          complete: function () {
            $element.text(targetNumber);
          },
        },
      );
    },

    exportSettings: function (e) {
      e.preventDefault();

      const settings = {
        version: "1.0.0",
        timestamp: new Date().toISOString(),
        whitelist: [],
        security_enabled: $('input[name="security_enabled"]').is(":checked"),
      };

      $('input[name="whitelist_plugins[]"]:checked').each(function () {
        settings.whitelist.push($(this).val());
      });

      const dataStr = JSON.stringify(settings, null, 2);
      const dataBlob = new Blob([dataStr], { type: "application/json" });

      const link = document.createElement("a");
      link.href = URL.createObjectURL(dataBlob);
      link.download =
        "security-guardian-settings-" +
        new Date().toISOString().split("T")[0] +
        ".json";
      link.click();

      SecurityGuardian.showNotification(
        "Nastavení bylo exportováno",
        "success",
      );
    },

    importSettings: function (e) {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = function (event) {
        try {
          const settings = JSON.parse(event.target.result);

          if (!settings.whitelist || !Array.isArray(settings.whitelist)) {
            throw new Error("Neplatný formát souboru");
          }

          // Resetovat všechny checkboxy
          $('input[name="whitelist_plugins[]"]').prop("checked", false);

          // Nastavit podle importu
          settings.whitelist.forEach(function (pluginPath) {
            $(
              'input[name="whitelist_plugins[]"][value="' + pluginPath + '"]',
            ).prop("checked", true);
          });

          if (typeof settings.security_enabled !== "undefined") {
            $('input[name="security_enabled"]').prop(
              "checked",
              settings.security_enabled,
            );
          }

          SecurityGuardian.updateStats();
          SecurityGuardian.showNotification(
            "Nastavení bylo importováno",
            "success",
          );
        } catch (error) {
          SecurityGuardian.showNotification(
            "Chyba při importu: " + error.message,
            "error",
          );
        }
      };
      reader.readAsText(file);
    },

    confirmSubmit: function (e) {
      // Počítat jen povolené (ne disabled) checkboxy
      const enabledCount = $(
        'input[name="whitelist_plugins[]"]:checked:not(:disabled)',
      ).length;
      const totalCount = $(
        'input[name="whitelist_plugins[]"]:not(:disabled)',
      ).length;

      if (enabledCount === 0) {
        if (
          !confirm(
            "Pozor! Nepovolíte žádné pluginy. Tím zablokujete aktivaci všech pluginů kromě Security Guardian. Pokračovat?",
          )
        ) {
          e.preventDefault();
          return false;
        }
      }

      if (enabledCount === totalCount && totalCount > 0) {
        if (
          !confirm(
            "Povolujete všechny pluginy. Tím se vypne bezpečnostní ochrana. Pokračovat?",
          )
        ) {
          e.preventDefault();
          return false;
        }
      }

      // Zobrazit loading indikátor
      $(this)
        .find('button[type="submit"]')
        .addClass("wpsg-loading")
        .prop("disabled", true);

      // Použít správnou třídu nebo wrapper
      const wrapper = $(".wrap, .wpsg-admin-page").first();
      if (wrapper.length) {
        wrapper.addClass("wpsg-loading");
      }

      // DŮLEŽITÉ: Povolit odeslání formuláře
      return true;
    },

    initTooltips: function () {
      $(".wpsg-tooltip").each(function () {
        $(this).hover(
          function () {
            const tooltip = $(
              '<div class="wpsg-tooltip-content">' +
                $(this).data("tooltip") +
                "</div>",
            );
            $("body").append(tooltip);

            const offset = $(this).offset();
            tooltip.css({
              position: "absolute",
              top: offset.top - tooltip.outerHeight() - 5,
              left:
                offset.left +
                $(this).outerWidth() / 2 -
                tooltip.outerWidth() / 2,
              zIndex: 1000,
            });
          },
          function () {
            $(".wpsg-tooltip-content").remove();
          },
        );
      });
    },

    initSearchFilter: function () {
      // Přidat search box pokud neexistuje
      if ($("#wpsg-search").length === 0) {
        const searchBox = `
                    <div class="wpsg-search-box mb-4">
                        <input type="text" id="wpsg-search" placeholder="Hledat pluginy..." 
                               class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    </div>
                `;
        $(".wpsg-plugin-list").before(searchBox);
      }
    },

    initBulkActions: function () {
      // Přidat bulk action tlačítka pokud neexistují
      if ($(".wpsg-bulk-actions").length === 0) {
        const bulkActions = `
                    <div class="wpsg-bulk-actions flex space-x-2 mb-4">
                        <button type="button" id="wpsg-select-all" class="px-3 py-1 text-sm border border-gray-300 rounded hover:bg-gray-50">
                            Vybrat vše
                        </button>
                        <button type="button" id="wpsg-bulk-enable" class="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700">
                            Povolit vybrané
                        </button>
                        <button type="button" id="wpsg-bulk-disable" class="px-3 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700">
                            Zakázat vybrané
                        </button>
                        <button type="button" id="wpsg-export" class="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700">
                            Export
                        </button>
                        <label for="wpsg-import" class="px-3 py-1 text-sm bg-gray-600 text-white rounded hover:bg-gray-700 cursor-pointer">
                            Import
                            <input type="file" id="wpsg-import" accept=".json" class="hidden">
                        </label>
                    </div>
                `;
        $(".wpsg-plugin-list").before(bulkActions);
      }
    },

    showWelcomeMessage: function () {
      if (localStorage.getItem("wpsg_welcome_shown") !== "true") {
        setTimeout(function () {
          SecurityGuardian.showNotification(
            "Vítejte v Security Guardian! Vyberte pluginy, které chcete povolit k aktivaci.",
            "info",
            5000,
          );
          localStorage.setItem("wpsg_welcome_shown", "true");
        }, 1000);
      }
    },

    showNotification: function (message, type = "info", duration = 3000) {
      const notification = $(`
                <div class="wpsg-notification fixed top-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 ${this.getNotificationClass(
                  type,
                )}">
                    <div class="flex items-center">
                        <span class="mr-2">${this.getNotificationIcon(
                          type,
                        )}</span>
                        <span>${message}</span>
                        <button class="ml-4 text-xl leading-none">&times;</button>
                    </div>
                </div>
            `);

      $("body").append(notification);

      // Auto hide
      setTimeout(function () {
        notification.fadeOut(300, function () {
          $(this).remove();
        });
      }, duration);

      // Manual close
      notification.find("button").on("click", function () {
        notification.fadeOut(300, function () {
          $(this).remove();
        });
      });
    },

    getNotificationClass: function (type) {
      const classes = {
        success: "bg-green-500 text-white",
        error: "bg-red-500 text-white",
        warning: "bg-yellow-500 text-white",
        info: "bg-blue-500 text-white",
      };
      return classes[type] || classes.info;
    },

    getNotificationIcon: function (type) {
      const icons = {
        success: "✓",
        error: "✗",
        warning: "⚠",
        info: "ℹ",
      };
      return icons[type] || icons.info;
    },

    animateButton: function (e) {
      if (e.type === "mouseenter") {
        $(this).addClass(
          "transform scale-105 transition-transform duration-200",
        );
      } else {
        $(this).removeClass(
          "transform scale-105 transition-transform duration-200",
        );
      }
    },
  };

  // Inicializace
  SecurityGuardian.init();

  // Aktualizace statistik při načtení stránky
  SecurityGuardian.updateStats();

  // Globální přístup pro debugging
  window.SecurityGuardian = SecurityGuardian;
});
