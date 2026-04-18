package com.flow.validator.ui.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;

/**
 * LogAdapter — RecyclerView adapter for the real-time filtered event log.
 *
 * Uses view recycling for high-frequency log streams without UI jank.
 * Log lines are expected to be pre-formatted strings.
 */
public class LogAdapter extends RecyclerView.Adapter<LogAdapter.LogViewHolder> {

    private final List<String> items;

    public LogAdapter(List<String> items) {
        this.items = items;
    }

    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(android.R.layout.simple_list_item_1, parent, false);
        return new LogViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        String line = items.get(position);
        holder.textView.setText(line);

        // Colour-code BLOCKED vs generic audit lines
        if (line.contains("BLOCKED")) {
            holder.textView.setTextColor(0xFFFF7B72); // red-ish
        } else {
            holder.textView.setTextColor(0xFF8B949E); // muted grey
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class LogViewHolder extends RecyclerView.ViewHolder {
        final TextView textView;

        LogViewHolder(@NonNull View itemView) {
            super(itemView);
            textView = itemView.findViewById(android.R.id.text1);
            textView.setTextSize(11f);
            textView.setTypeface(android.graphics.Typeface.MONOSPACE);
            textView.setPadding(8, 4, 8, 4);
        }
    }
}
