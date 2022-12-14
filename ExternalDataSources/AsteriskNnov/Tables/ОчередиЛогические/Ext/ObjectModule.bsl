Процедура ПередЗаписью(Отказ)

// Принудительно проверим заполнение
//-------------------------------------------------------------------------------------------------
	Если (НЕ ЭтотОбъект.ПроверитьЗаполнение()) Тогда
		Отказ = Истина;
		Возврат;
	КонецЕсли;

// Нормализуем некоторые реквизиты
//-------------------------------------------------------------------------------------------------
	ЭтотОбъект.Телефон = ВРег(СокрЛП(ЭтотОбъект.Телефон));
	ЭтотОбъект.Комментарий = СокрЛП(ЭтотОбъект.Комментарий);
	ЭтотОбъект.КодПроекта = ВРег(СокрЛП(ЭтотОбъект.КодПроекта));
	ЭтотОбъект.Наименование = ВРег(СокрЛП(ЭтотОбъект.Наименование));

// Проверим на дублирование по системной очереди
//-------------------------------------------------------------------------------------------------
	Если (ЭтотОбъект.Наименование <> ЭтотОбъект.Ссылка.Наименование) Тогда
		ТекстЗапроса = "
		|SELECT	COUNT(*) AS Всего
		|FROM	ВнешнийИсточникДанных.AsteriskNnov.Таблица.ОчередиЛогические
		|WHERE	(Ссылка <> &ЭтотОбъект) И (Наименование = &Наименование)";

		Запрос = Новый Запрос(ТекстЗапроса);
		Запрос.УстановитьПараметр("ЭтотОбъект",ЭтотОбъект.Ссылка);
		Запрос.УстановитьПараметр("Наименование",СокрЛП(ЭтотОбъект.Наименование));
		Результат = Запрос.Выполнить().Выбрать();

		Если (Результат.Следующий()) И (Результат.Всего > 0) Тогда
			Сообщить("Логическая очередь с указанным наименованием уже существует");
			Отказ = Истина;
			Возврат;
		КонецЕсли;
	КонецЕсли;

// Проверим на дублирование по номеру телефона очереди (при его заполненности)
//-------------------------------------------------------------------------------------------------
	Доступно = (ЭтотОбъект.Телефон <> ЭтотОбъект.Ссылка.Телефон);
	Доступно = Доступно И ЗначениеЗаполнено(ЭтотОбъект.Телефон);

	Если (Доступно = Истина) Тогда
		ТекстЗапроса = "
		|SELECT	COUNT(*) AS Всего
		|FROM	ВнешнийИсточникДанных.AsteriskNnov.Таблица.ОчередиЛогические
		|WHERE	(Ссылка <> &ЭтотОбъект) И (Телефон = &Телефон)";

		Запрос = Новый Запрос(ТекстЗапроса);
		Запрос.УстановитьПараметр("ЭтотОбъект",ЭтотОбъект.Ссылка);
		Запрос.УстановитьПараметр("Телефон",ЭтотОбъект.Телефон);
		Результат = Запрос.Выполнить().Выбрать();

		Если (Результат.Следующий()) И (Результат.Всего > 0) Тогда
			Сообщить("Логическая очередь с указанным номером телефона уже существует");
			Отказ = Истина;
			Возврат;
		КонецЕсли;
	КонецЕсли;
КонецПроцедуры
