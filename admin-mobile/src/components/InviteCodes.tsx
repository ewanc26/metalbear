import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, FlatList, StyleSheet, Text, TouchableOpacity, View } from 'react-native';
import { useAdminSession } from '../context/AdminSessionContext';
import { adminDisableInviteCodes, adminGetInviteCodes, type AdminInviteCode } from '../api/pds';
import { colors } from '../theme';

export function InviteCodes() {
	const { session } = useAdminSession();
	const [codes, setCodes] = useState<AdminInviteCode[]>([]);
	const [cursor, setCursor] = useState<string | undefined>(undefined);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState('');
	const [disabling, setDisabling] = useState<string | null>(null);

	const load = useCallback(
		async (nextCursor?: string) => {
			if (!session) return;
			setLoading(true);
			setError('');
			try {
				const result = await adminGetInviteCodes(session, nextCursor);
				setCodes((prev) => (nextCursor ? [...prev, ...result.codes] : result.codes));
				setCursor(result.cursor);
			} catch (err) {
				setError(err instanceof Error ? err.message : 'Failed to load invite codes');
			} finally {
				setLoading(false);
			}
		},
		[session]
	);

	useEffect(() => {
		load();
	}, [load]);

	async function handleDisable(code: string) {
		if (!session) return;
		setDisabling(code);
		try {
			await adminDisableInviteCodes(session, [code]);
			await load();
		} catch (err) {
			setError(err instanceof Error ? err.message : 'Failed to disable code');
		} finally {
			setDisabling(null);
		}
	}

	if (!session) return null;

	return (
		<View style={styles.section}>
			<Text style={styles.sectionTitle}>INVITE CODES</Text>

			{error ? <Text style={styles.error}>{error}</Text> : null}

			{loading && codes.length === 0 ? (
				<Text style={styles.muted}>Loading…</Text>
			) : codes.length === 0 ? (
				<Text style={styles.muted}>No invite codes.</Text>
			) : (
				<FlatList
					data={codes}
					keyExtractor={(c) => c.code}
					scrollEnabled={false}
					ItemSeparatorComponent={() => <View style={styles.separator} />}
					renderItem={({ item }) => (
						<View style={styles.row}>
							<View style={styles.flex}>
								<Text style={styles.code}>{item.code}</Text>
								<Text style={styles.meta}>
									{item.uses.length}/{item.available < 0 ? '∞' : item.available} used · for{' '}
									{item.forAccount}
									{item.disabled ? ' · disabled' : ''}
								</Text>
							</View>
							{!item.disabled && (
								<TouchableOpacity
									disabled={disabling === item.code}
									onPress={() => handleDisable(item.code)}
								>
									<Text style={styles.disableLink}>
										{disabling === item.code ? 'Disabling…' : 'Disable'}
									</Text>
								</TouchableOpacity>
							)}
						</View>
					)}
					ListFooterComponent={
						cursor ? (
							<TouchableOpacity
								style={[styles.loadMore, loading && styles.buttonDisabled]}
								disabled={loading}
								onPress={() => load(cursor)}
							>
								{loading ? (
									<ActivityIndicator color={colors.text} size="small" />
								) : (
									<Text style={styles.loadMoreText}>Load more</Text>
								)}
							</TouchableOpacity>
						) : null
					}
				/>
			)}
		</View>
	);
}

const styles = StyleSheet.create({
	section: { borderWidth: 1, borderColor: colors.border, borderRadius: 12, padding: 16 },
	sectionTitle: {
		fontSize: 12,
		fontWeight: '700',
		letterSpacing: 1,
		color: colors.textMuted,
		marginBottom: 12
	},
	muted: { color: colors.textMuted, fontSize: 13 },
	error: {
		color: colors.danger,
		backgroundColor: colors.dangerBackground,
		borderWidth: 1,
		borderColor: colors.dangerBorder,
		borderRadius: 8,
		padding: 10,
		marginBottom: 12,
		fontSize: 13
	},
	row: { flexDirection: 'row', alignItems: 'center', paddingVertical: 10, gap: 12 },
	flex: { flex: 1 },
	code: { color: colors.text, fontSize: 13, fontFamily: 'Menlo' },
	meta: { color: colors.textMuted, fontSize: 12, marginTop: 3 },
	disableLink: { color: '#f87171', fontSize: 13 },
	separator: { height: 1, backgroundColor: colors.border },
	loadMore: {
		marginTop: 12,
		borderWidth: 1,
		borderColor: colors.borderStrong,
		borderRadius: 8,
		paddingVertical: 10,
		alignItems: 'center'
	},
	loadMoreText: { color: colors.text, fontSize: 13 },
	buttonDisabled: { opacity: 0.5 }
});
