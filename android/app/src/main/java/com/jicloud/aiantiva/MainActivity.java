package com.jicloud.aiantiva;

import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import android.app.Activity;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final int PICK_MODEL = 1001;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private TextView scanResult;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildScreen());
    }

    private View buildScreen() {
        int navy = Color.rgb(9, 21, 38);
        int blue = Color.rgb(22, 103, 199);
        int muted = Color.rgb(96, 117, 138);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(22), dp(24), dp(28));
        root.setBackgroundColor(Color.rgb(247, 251, 254));
        scroll.addView(root);

        LinearLayout brand = new LinearLayout(this);
        brand.setGravity(Gravity.CENTER_VERTICAL);
        ImageView icon = new ImageView(this);
        icon.setImageResource(com.jicloud.aiantiva.R.drawable.ic_antiva);
        brand.addView(icon, new LinearLayout.LayoutParams(dp(64), dp(64)));

        LinearLayout brandText = new LinearLayout(this);
        brandText.setOrientation(LinearLayout.VERTICAL);
        brandText.setPadding(dp(14), 0, 0, 0);
        TextView name = text("JICloud", 28, navy, true);
        TextView product = text("AI ANTIVA", 13, blue, true);
        brandText.addView(name);
        brandText.addView(product);
        brand.addView(brandText, new LinearLayout.LayoutParams(0, -2, 1));
        root.addView(brand);

        TextView tagline = text("선택한 모델 파일의 로컬 해시 검사", 15, muted, false);
        tagline.setPadding(0, dp(14), 0, dp(22));
        root.addView(tagline);

        LinearLayout statusCard = card();
        TextView statusLabel = text("보호 상태", 13, muted, true);
        statusCard.addView(statusLabel);
        status = text("준비됨", 25, blue, true);
        status.setPadding(0, dp(5), 0, dp(3));
        statusCard.addView(status);
        statusCard.addView(text("현재 앱은 선택 파일의 SHA-256과 확장자만 확인합니다.", 14, muted, false));
        root.addView(statusCard);

        Button scan = new Button(this);
        scan.setText("모델 파일 검사");
        scan.setTextColor(Color.WHITE);
        scan.setBackgroundColor(blue);
        scan.setAllCaps(false);
        scan.setOnClickListener(view -> openModelPicker());
        LinearLayout.LayoutParams scanParams = new LinearLayout.LayoutParams(-1, dp(52));
        scanParams.setMargins(0, dp(20), 0, dp(10));
        root.addView(scan, scanParams);

        scanResult = text("검사할 모델 파일을 선택하세요.\n모델을 실행하거나 역직렬화하지 않습니다.", 14, muted, false);
        scanResult.setPadding(dp(16), dp(16), dp(16), dp(16));
        scanResult.setBackgroundColor(Color.WHITE);
        root.addView(scanResult);

        TextView note = text("이 앱은 악성 모델 판정이나 기기 보호 기능을 아직 제공하지 않습니다.", 13, muted, false);
        note.setPadding(0, dp(22), 0, 0);
        root.addView(note);
        return scroll;
    }

    private LinearLayout card() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(18), dp(16), dp(18), dp(16));
        card.setBackgroundColor(Color.WHITE);
        return card;
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setTypeface(null, bold ? android.graphics.Typeface.BOLD : android.graphics.Typeface.NORMAL);
        return view;
    }

    private void openModelPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, PICK_MODEL);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_MODEL && resultCode == RESULT_OK && data != null && data.getData() != null) {
            scanUri(data.getData());
        }
    }

    private void scanUri(Uri uri) {
        status.setText("검사 중...");
        scanResult.setText("파일을 읽고 있습니다. 모델은 실행하지 않습니다.");
        executor.execute(() -> {
            try {
                String name = displayName(uri);
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                long size = 0;
                try (InputStream input = getContentResolver().openInputStream(uri)) {
                    if (input == null) throw new IllegalStateException("파일을 열 수 없습니다.");
                    byte[] buffer = new byte[1024 * 1024];
                    int read;
                    while ((read = input.read(buffer)) != -1) {
                        digest.update(buffer, 0, read);
                        size += read;
                    }
                }
                String hash = hex(digest.digest());
                String result = buildResult(name, size, hash);
                runOnUiThread(() -> {
                    status.setText("검사 완료");
                    scanResult.setText(result);
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    status.setText("검사 실패");
                    scanResult.setText("오류: " + error.getMessage());
                });
            }
        });
    }

    private String buildResult(String name, long size, String hash) {
        String lower = name.toLowerCase(Locale.ROOT);
        String warning = "파일 내용 검증은 아직 제공하지 않습니다.";
        if (lower.endsWith(".pt") || lower.endsWith(".pth") || lower.endsWith(".pkl") || lower.endsWith(".pickle")) {
            warning = "주의: 확장자상 역직렬화가 필요할 수 있는 포맷입니다. 샌드박스 로더가 필요합니다.";
        } else if (lower.endsWith(".bin") || lower.endsWith(".ckpt")) {
            warning = "주의: 확장자만으로 포맷을 확인할 수 없습니다. 신뢰할 수 있는 출처를 확인하세요.";
        }
        return "파일: " + name + "\n크기: " + size + " bytes\nSHA-256: " + hash + "\n\n" + warning;
    }

    private String displayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (index >= 0) return cursor.getString(index);
            }
        }
        return uri.getLastPathSegment() == null ? "selected-model" : uri.getLastPathSegment();
    }

    private String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format(Locale.ROOT, "%02x", value));
        return result.toString();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
