import React, { useState } from 'react';
import {
	ActivityIndicator,
	KeyboardAvoidingView,
	Platform,
	StyleSheet,
	Text,
	TextInput,
	TouchableOpacity,
	View
} from 'react-native';
import { useAdminSession } from '../context/AdminSessionContext';
import { colors } from '../theme';

export function LoginScreen() {
	const { login } = useAdminSession();
	const [serviceUrl, setServiceUrl] = useState('https://');
	const [password, setPassword] = useState('');
	const [pending, setPending] = useState(false);
	const [error, setError] = useState('');

	async function handleSubmit() {
		setError('');
		setPending(true);
		try {
			await login(serviceUrl.trim(), password);
		} catch (err) {
			setError(err instanceof Error ? err.message : 'Login failed');
		} finally {
			setPending(false);
		}
	}

	const canSubmit = serviceUrl.trim().length > 8 && password.length > 0 && !pending;

	return (
		<KeyboardAvoidingView
			style={styles.flex}
			behavior={Platform.OS === 'ios' ? 'padding' : undefined}
		>
			<View style={styles.container}>
				<Text style={styles.title}>PDS Admin</Text>
				<Text style={styles.subtitle}>Sign in with a server's admin password</Text>

				<View style={styles.field}>
					<Text style={styles.label}>PDS URL</Text>
					<TextInput
						value={serviceUrl}
						onChangeText={setServiceUrl}
						placeholder="https://bear1.croft.click"
						placeholderTextColor={colors.textMuted}
						autoCapitalize="none"
						autoCorrect={false}
						keyboardType="url"
						style={styles.input}
					/>
				</View>

				<View style={styles.field}>
					<Text style={styles.label}>Admin password</Text>
					<TextInput
						value={password}
						onChangeText={setPassword}
						placeholder="Admin password"
						placeholderTextColor={colors.textMuted}
						secureTextEntry
						autoCapitalize="none"
						autoCorrect={false}
						style={styles.input}
						onSubmitEditing={canSubmit ? handleSubmit : undefined}
					/>
				</View>

				{error ? <Text style={styles.error}>{error}</Text> : null}

				<TouchableOpacity
					style={[styles.button, !canSubmit && styles.buttonDisabled]}
					disabled={!canSubmit}
					onPress={handleSubmit}
				>
					{pending ? (
						<ActivityIndicator color={colors.buttonText} />
					) : (
						<Text style={styles.buttonText}>Sign in</Text>
					)}
				</TouchableOpacity>
			</View>
		</KeyboardAvoidingView>
	);
}

const styles = StyleSheet.create({
	flex: { flex: 1, backgroundColor: colors.background },
	container: { flex: 1, justifyContent: 'center', padding: 24 },
	title: { fontSize: 28, fontWeight: '700', color: colors.text, marginBottom: 4 },
	subtitle: { fontSize: 14, color: colors.textMuted, marginBottom: 32 },
	field: { marginBottom: 16 },
	label: { fontSize: 13, color: colors.textMuted, marginBottom: 6, fontWeight: '600' },
	input: {
		borderWidth: 1,
		borderColor: colors.border,
		borderRadius: 10,
		paddingHorizontal: 14,
		paddingVertical: 12,
		fontSize: 15,
		color: colors.text,
		backgroundColor: colors.surface
	},
	error: {
		color: colors.danger,
		backgroundColor: colors.dangerBackground,
		borderWidth: 1,
		borderColor: colors.dangerBorder,
		borderRadius: 10,
		padding: 12,
		marginBottom: 16,
		fontSize: 13
	},
	button: {
		backgroundColor: colors.accent,
		borderRadius: 10,
		paddingVertical: 14,
		alignItems: 'center',
		marginTop: 8
	},
	buttonDisabled: { opacity: 0.5 },
	buttonText: { color: colors.buttonText, fontSize: 15, fontWeight: '600' }
});
