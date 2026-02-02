package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class McpContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;

    public McpContextMenuProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Check if we have a request/response selected
        Optional<MessageEditorHttpRequestResponse> messageEditor = event.messageEditorRequestResponse();

        if (messageEditor.isPresent()) {
            HttpRequestResponse requestResponse = messageEditor.get().requestResponse();

            JMenuItem sendToOrganizerItem = new JMenuItem("Send to Organizer (MCP Bridge)");
            sendToOrganizerItem.addActionListener(e -> {
                sendToOrganizer(requestResponse);
            });

            menuItems.add(sendToOrganizerItem);
        }

        // Also check for selected HTTP request/responses from other contexts
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (!selectedItems.isEmpty() && selectedItems.size() == 1) {
            HttpRequestResponse requestResponse = selectedItems.get(0);

            JMenuItem sendToOrganizerItem = new JMenuItem("Send to Organizer (MCP Bridge)");
            sendToOrganizerItem.addActionListener(e -> {
                sendToOrganizer(requestResponse);
            });

            menuItems.add(sendToOrganizerItem);
        } else if (selectedItems.size() > 1) {
            // Handle multiple selections
            JMenuItem sendMultipleItem = new JMenuItem("Send " + selectedItems.size() + " items to Organizer");
            sendMultipleItem.addActionListener(e -> {
                for (HttpRequestResponse item : selectedItems) {
                    sendToOrganizer(item);
                }
                showMultipleSuccessMessage(selectedItems.size());
            });

            menuItems.add(sendMultipleItem);
        }

        return menuItems;
    }

    private void sendToOrganizer(HttpRequestResponse requestResponse) {
        try {
            api.organizer().sendToOrganizer(requestResponse);
            showSuccessMessage(requestResponse.request().url());
        } catch (Exception e) {
            api.logging().logToError("Failed to send to organizer: " + e.getMessage());
            JOptionPane.showMessageDialog(
                null,
                "Failed to send to Organizer: " + e.getMessage(),
                "MCP Bridge Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void showSuccessMessage(String url) {
        JOptionPane.showMessageDialog(
            null,
            "Request sent to Burp Organizer!\n\nURL: " + truncateUrl(url) + "\n\n" +
            "Access from Claude using burp_organizer tool.",
            "Sent to Organizer",
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    private void showMultipleSuccessMessage(int count) {
        JOptionPane.showMessageDialog(
            null,
            count + " items sent to Burp Organizer!\n\n" +
            "Access from Claude using burp_organizer tool.",
            "Sent to Organizer",
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    private String truncateUrl(String url) {
        if (url.length() > 80) {
            return url.substring(0, 77) + "...";
        }
        return url;
    }
}
